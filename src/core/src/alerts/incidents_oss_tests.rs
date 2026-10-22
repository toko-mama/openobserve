// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use sea_orm::{ConnectionTrait, Schema};
use svix_ksuid::KsuidLike;

use super::*;

async fn setup() {
    std::fs::create_dir_all(&config::get_config().common.data_db_dir).unwrap();
    let db = infra::db::get_orm_client_rw().await;
    let schema = Schema::new(db.get_database_backend());
    for mut statement in [
        schema.create_table_from_entity(infra::table::entity::alert_incidents::Entity),
        schema.create_table_from_entity(infra::table::entity::alert_incident_alerts::Entity),
        schema.create_table_from_entity(infra::table::entity::incident_events::Entity),
        schema.create_table_from_entity(infra::table::entity::folders::Entity),
        schema.create_table_from_entity(infra::table::entity::alerts::Entity),
        schema.create_table_from_entity(infra::table::entity::alert_composites::Entity),
        schema.create_table_from_entity(infra::table::entity::alert_composite_children::Entity),
    ] {
        db.execute(db.get_database_backend().build(statement.if_not_exists()))
            .await
            .unwrap();
    }
}

async fn cleanup(org: &str) {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    let ids = store::list(org, None, 500, 0)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.id)
        .collect::<Vec<_>>();
    infra::table::entity::alert_incident_alerts::Entity::delete_many()
        .filter(infra::table::entity::alert_incident_alerts::Column::IncidentId.is_in(ids))
        .exec(infra::db::get_orm_client_rw().await)
        .await
        .unwrap();
    infra::table::incident_events::delete_by_org(org)
        .await
        .unwrap();
    infra::table::alert_incidents::delete_by_org(org)
        .await
        .unwrap();
}

fn alert(org: &str, name: &str) -> Alert {
    let mut value = Alert::default();
    value.id = Some(svix_ksuid::Ksuid::new(None, None));
    value.org_id = org.into();
    value.name = name.into();
    value.creates_incident = true;
    value
}

#[tokio::test]
async fn incidents_oss_persistent_lifecycle_and_actor_events() {
    setup().await;
    let org = format!("oss-test-{}", svix_ksuid::Ksuid::new(None, None));
    let a = alert(&org, "Errors");
    common::infra::config::ALERTS.write().await.insert(
        db::alerts::alert::cache_alert_key(&org, &a.get_unique_key()),
        (config::meta::folder::Folder::default(), a.clone()),
    );
    let row = Map::new();
    let first = correlate_firing(&a, &row, 1, &[]).await.unwrap();
    let id = first.incident_id();
    assert!(matches!(
        first,
        IncidentCorrelationOutcome::NewIncidentCreated { .. }
    ));
    assert_eq!(
        get_incident_with_alerts(&org, id)
            .await
            .unwrap()
            .unwrap()
            .incident
            .severity,
        IncidentSeverity::P3
    );
    assert!(
        get_incident_with_alerts("other-org", id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        update_status("other-org", id, "resolved", "intruder")
            .await
            .is_err()
    );
    assert!(
        add_comment("other-org", id, "intruder", "no")
            .await
            .is_err()
    );
    update_status(&org, id, "acknowledged", "operator")
        .await
        .unwrap();
    let repeated = correlate_firing(&a, &row, 2, &[]).await.unwrap();
    assert!(matches!(
        repeated,
        IncidentCorrelationOutcome::ExistingAlertRepeated { .. }
    ));
    assert_eq!(repeated.incident_id(), id);
    assert!(notification_event(&repeated).is_none());
    let detail = get_incident_with_alerts(&org, id).await.unwrap().unwrap();
    assert_eq!(detail.triggers.len(), 2);
    assert_eq!(detail.incident.status.to_string(), "acknowledged");
    assert_eq!(detail.incident.acknowledged_by.as_deref(), Some("operator"));
    add_comment(&org, id, "operator", "Investigating")
        .await
        .unwrap();
    update_title(&org, id, "API errors", "operator")
        .await
        .unwrap();
    update_severity(&org, id, "P1", "operator").await.unwrap();
    assert!(update_severity(&org, id, "P5", "operator").await.is_err());
    assert!(
        update_status(&org, id, "invalid", "operator")
            .await
            .is_err()
    );
    let events = get_events(&org, id).await.unwrap();
    assert!(events.iter().any(|e| matches!(&e.event_type, config::meta::alerts::incidents::IncidentEventType::Comment {user_id, comment} if user_id == "operator" && comment == "Investigating")));
    assert!(events.iter().any(|e| matches!(&e.event_type, config::meta::alerts::incidents::IncidentEventType::SeverityOverride {user_id, ..} if user_id == "operator")));
    update_status(&org, id, "resolved", "operator")
        .await
        .unwrap();
    let next = correlate_firing(&a, &row, 3, &[]).await.unwrap();
    assert_ne!(id, next.incident_id());
    let reopened = update_status(&org, id, "open", "operator").await.unwrap();
    assert!(reopened.resolved_at.is_none());
    assert!(reopened.acknowledged_by.is_none());
    assert_eq!(list_incidents(&org, None, 1, 1).await.unwrap().0.len(), 1);
    assert_eq!(get_incident_stats(&org).await.unwrap().total_incidents, 2);
    cleanup(&org).await;
}

#[tokio::test]
async fn incidents_oss_concurrent_matching_alerts_create_once_and_join_notifies_once() {
    setup().await;
    let org = format!("oss-concurrent-{}", svix_ksuid::Ksuid::new(None, None));
    let a = alert(&org, "Errors");
    let b = alert(&org, "Latency");
    for item in [&a, &b] {
        common::infra::config::ALERTS.write().await.insert(
            db::alerts::alert::cache_alert_key(&org, &item.get_unique_key()),
            (config::meta::folder::Folder::default(), item.clone()),
        );
    }
    let fields = vec!["service".into()];
    let row = serde_json::from_value(serde_json::json!({"service": "api"})).unwrap();
    let (first, second) = tokio::join!(
        correlate_firing(&a, &row, 1, &fields),
        correlate_firing(&b, &row, 2, &fields)
    );
    let first = first.unwrap();
    let second = second.unwrap();
    assert_eq!(first.incident_id(), second.incident_id());
    let events = [notification_event(&first), notification_event(&second)];
    assert!(events.contains(&Some("new_incident_created")));
    assert!(events.contains(&Some("new_alert_correlated")));
    assert_eq!(list_incidents(&org, None, 10, 0).await.unwrap().1, 1);
    let mut other_org = a.clone();
    other_org.org_id.push_str("-other");
    let other = correlate_firing(&other_org, &row, 1, &fields)
        .await
        .unwrap();
    assert_ne!(first.incident_id(), other.incident_id());
    let (repeat_a, repeat_b) = tokio::join!(
        correlate_firing(&a, &row, 3, &fields),
        correlate_firing(&a, &row, 4, &fields)
    );
    assert!(notification_event(&repeat_a.unwrap()).is_none());
    assert!(notification_event(&repeat_b.unwrap()).is_none());
    for test_org in [&org, &other_org.org_id] {
        cleanup(test_org).await;
    }
}

#[tokio::test]
async fn incidents_oss_recovery_checks_organization_and_preserves_acknowledgment() {
    setup().await;
    let org = format!("oss-recovery-{}", svix_ksuid::Ksuid::new(None, None));
    let a = alert(&org, "Errors");
    let first = correlate_firing(&a, &Map::new(), 1, &[]).await.unwrap();
    let id = first.incident_id();
    let mut recovery = RecoveryEvent {
        org_id: "another-org".into(),
        alert_id: a.get_unique_key(),
        group_key: String::new(),
        episode_id: "episode".into(),
        incident_id: Some(id.into()),
        opened_at: 1,
        recovered_at: 10,
        emitted_at: 10,
        last_notified_level: None,
        group_labels: None,
    };
    assert!(resolve_alert_firing(&recovery).await.is_err());
    assert!(
        store::get_incident_alerts(id)
            .await
            .unwrap()
            .iter()
            .all(|link| link.resolved_at.is_none())
    );
    recovery.org_id = org.clone();
    update_status(&org, id, "acknowledged", "operator")
        .await
        .unwrap();
    resolve_alert_firing(&recovery).await.unwrap();
    assert_eq!(
        require_incident(&org, id).await.unwrap().status,
        "acknowledged"
    );
    update_status(&org, id, "open", "operator").await.unwrap();
    resolve_alert_firing(&recovery).await.unwrap();
    assert_eq!(require_incident(&org, id).await.unwrap().status, "resolved");
    cleanup(&org).await;
}

#[tokio::test]
async fn incidents_oss_notification_errors_propagate_to_the_alert_caller() {
    setup().await;
    let org = format!("oss-notify-{}", svix_ksuid::Ksuid::new(None, None));
    let mut a = alert(&org, "Errors");
    a.destinations = vec!["invalid".into()];
    common::infra::config::DESTINATIONS.insert(
        format!("{org}/invalid"),
        config::meta::destinations::Destination {
            org_id: org.clone(),
            name: "invalid".into(),
            module: config::meta::destinations::Module::Pipeline {
                endpoint: Default::default(),
            },
            ..Default::default()
        },
    );
    let rows = [Map::new()];
    let error = correlate_alert_to_incident(&a, &rows[0], &rows, 1, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Incident notification failed"));
    assert!(error.to_string().contains("Not an alert destination"));
    assert_eq!(store::count(&org, None).await.unwrap(), 1);
    common::infra::config::DESTINATIONS.remove(&format!("{org}/invalid"));
    cleanup(&org).await;
}

#[test]
fn incidents_oss_notification_contract_and_destination_deduplication() {
    let mut a = alert("org", "Errors");
    a.stream_name = "logs".into();
    a.destinations = vec!["slack".into(), "slack".into()];
    let mut b = alert("org", "Other");
    b.destinations = vec!["email".into(), "slack".into()];
    assert_eq!(
        notification_destinations(&[a.clone(), b]),
        BTreeSet::from(["email".into(), "slack".into()])
    );
    let model = Model {
        id: "incident".into(),
        org_id: "org".into(),
        status: "open".into(),
        severity: "P1".into(),
        group_values: serde_json::json!({"service": "api"}),
        key_type: "Primary".into(),
        topology_context: None,
        first_alert_at: 0,
        last_alert_at: 0,
        resolved_at: None,
        alert_count: 1,
        title: Some("API errors".into()),
        assigned_to: None,
        acknowledged_by: None,
        acknowledged_at: None,
        created_at: 0,
        updated_at: 0,
    };
    let payload = notification_payload(&model, "new_incident_created", 1_000_000, Some(&a));
    assert_eq!(payload["incident"]["severity"], "P1");
    assert_eq!(payload["incident"]["alert"]["stream"]["name"], "logs");
    assert_eq!(payload["incident"]["alert"]["name"], "Errors");
    assert_eq!(payload["incident"]["event"], "new_incident_created");
    assert_eq!(payload["incident"]["time"], "1970-01-01T00:00:01.000Z");
    assert!(
        payload["incident"]["url"]
            .as_str()
            .unwrap()
            .ends_with("/web/alerts/incidents/incident?org_identifier=org")
    );
}

#[test]
fn incidents_oss_rejects_invalid_pagination() {
    assert!(validate_pagination(0, 0).is_err());
    assert!(validate_pagination(501, 0).is_err());
    assert!(validate_pagination(20, u64::MAX).is_err());
    assert!(validate_pagination(20, 1).is_ok());
}

#[tokio::test]
async fn incidents_oss_pagination_uses_the_exact_offset() {
    setup().await;
    let org = format!("oss-page-{}", svix_ksuid::Ksuid::new(None, None));
    let a = alert(&org, "First");
    let b = alert(&org, "Second");
    let c = alert(&org, "Third");
    let first = correlate_firing(&a, &Map::new(), 1, &[]).await.unwrap();
    let second = correlate_firing(&b, &Map::new(), 2, &[]).await.unwrap();
    correlate_firing(&c, &Map::new(), 3, &[]).await.unwrap();
    let (page, count) = list_incidents(&org, None, 2, 1).await.unwrap();
    assert_eq!(count, 3);
    assert_eq!(
        page.iter()
            .map(|incident| incident.id.as_str())
            .collect::<Vec<_>>(),
        [second.incident_id(), first.incident_id()]
    );
    cleanup(&org).await;
}

#[tokio::test]
async fn incidents_oss_failed_delivery_remains_retryable_for_firing_and_same_severity() {
    setup().await;
    let org = format!("oss-retry-{}", svix_ksuid::Ksuid::new(None, None));
    let mut a = alert(&org, "Retry");
    a.destinations = vec!["invalid".into()];
    common::infra::config::ALERTS.write().await.insert(
        db::alerts::alert::cache_alert_key(&org, &a.get_unique_key()),
        (Default::default(), a.clone()),
    );
    common::infra::config::DESTINATIONS.insert(
        format!("{org}/invalid"),
        config::meta::destinations::Destination {
            org_id: org.clone(),
            name: "invalid".into(),
            module: config::meta::destinations::Module::Pipeline {
                endpoint: Default::default(),
            },
            ..Default::default()
        },
    );
    let rows = [Map::new()];
    assert!(
        correlate_alert_to_incident(&a, &rows[0], &rows, 1, None)
            .await
            .is_err()
    );
    assert!(
        correlate_alert_to_incident(&a, &rows[0], &rows, 2, None)
            .await
            .is_err(),
        "persisted firing is not successful notification delivery"
    );
    let id = store::list(&org, None, 10, 0).await.unwrap()[0].id.clone();
    assert!(update_severity(&org, &id, "P1", "operator").await.is_err());
    assert!(
        update_severity(&org, &id, "P1", "operator").await.is_err(),
        "same-severity retry must retry pending delivery"
    );
}

#[tokio::test]
async fn incidents_oss_event_storage_failure_rolls_back_mutation_and_actor_retry() {
    use sea_orm::Statement;
    setup().await;
    let org = format!("oss-rollback-{}", svix_ksuid::Ksuid::new(None, None));
    let a = alert(&org, "Rollback");
    let created = correlate_firing(&a, &Map::new(), 1, &[]).await.unwrap();
    let db = infra::db::get_orm_client_rw().await;
    let trigger = format!("fail_events_{}", a.get_unique_key());
    db.execute(Statement::from_string(db.get_database_backend(), format!("CREATE TRIGGER {trigger} BEFORE UPDATE ON incident_events WHEN NEW.org_id = '{org}' BEGIN SELECT RAISE(ABORT, 'injected event write failure'); END"))).await.unwrap();
    let result = update_status(&org, created.incident_id(), "acknowledged", "operator").await;
    let persisted = require_incident(&org, created.incident_id()).await.unwrap();
    let firing_result = correlate_firing(&a, &Map::new(), 2, &[]).await;
    let links = store::get_incident_alerts(created.incident_id())
        .await
        .unwrap();
    db.execute(Statement::from_string(
        db.get_database_backend(),
        format!("DROP TRIGGER {trigger}"),
    ))
    .await
    .unwrap();
    assert!(result.is_err());
    assert!(firing_result.is_err());
    assert_eq!(
        links.len(),
        1,
        "failed event must roll back the firing link"
    );
    assert_eq!(
        persisted.status, "open",
        "failed event append must roll back status"
    );
    update_status(&org, created.incident_id(), "acknowledged", "operator")
        .await
        .unwrap();
    assert!(get_events(&org, created.incident_id()).await.unwrap().iter().any(|event| matches!(&event.event_type, config::meta::alerts::incidents::IncidentEventType::Acknowledged { user_id } if user_id == "operator")));
}

#[tokio::test]
async fn incidents_oss_realtime_consumer_correlates_opt_in_and_preserves_normal_delivery() {
    setup().await;
    let org = format!("oss-realtime-{}", svix_ksuid::Ksuid::new(None, None));
    let mut a = alert(&org, "Realtime");
    a.is_real_time = true;
    let rows = [Map::new()];
    crate::ingestion::send_realtime_notification(&a, "trace", &rows, 1)
        .await
        .unwrap();
    assert_eq!(
        store::count(&org, None).await.unwrap(),
        1,
        "realtime opt-in creates an incident"
    );
    crate::ingestion::send_realtime_notification(&a, "trace", &rows, 2)
        .await
        .unwrap();
    assert_eq!(store::count(&org, None).await.unwrap(), 1);
    a.creates_incident = false;
    a.id = Some(svix_ksuid::Ksuid::new(None, None));
    crate::ingestion::send_realtime_notification(&a, "trace", &rows, 3)
        .await
        .unwrap();
    assert_eq!(store::count(&org, None).await.unwrap(), 1);
    a.creates_incident = true;
    let db = infra::db::get_orm_client_rw().await;
    let trigger = format!("fail_realtime_{}", a.get_unique_key());
    db.execute(sea_orm::Statement::from_string(db.get_database_backend(), format!("CREATE TRIGGER {trigger} BEFORE INSERT ON incident_events WHEN NEW.org_id = '{org}' BEGIN SELECT RAISE(ABORT, 'injected realtime incident failure'); END"))).await.unwrap();
    let fallback = crate::ingestion::send_realtime_notification(&a, "trace", &rows, 4).await;
    let count = store::count(&org, None).await.unwrap();
    db.execute(sea_orm::Statement::from_string(
        db.get_database_backend(),
        format!("DROP TRIGGER {trigger}"),
    ))
    .await
    .unwrap();
    assert!(
        fallback.is_ok(),
        "incident errors preserve the direct realtime path"
    );
    assert_eq!(count, 1, "failed incident transaction is rolled back");
}

#[tokio::test]
async fn incidents_oss_persisted_composite_keeps_summary_and_destinations() {
    setup().await;
    let org = format!("oss-composite-{}", svix_ksuid::Ksuid::new(None, None));
    let a = alert(&org, "Composite");
    persist_composite(&a, vec!["composite-destination".into()]).await;
    let first = correlate_firing(&a, &Map::new(), 1, &[]).await.unwrap();
    let detail = get_incident_with_alerts(&org, first.incident_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(detail.composite_alerts.len(), 1);
    assert!(detail.alerts.is_empty());
    assert_eq!(detail.composite_alerts[0].id, a.get_unique_key());
    let alerts = related_alerts(&org, first.incident_id(), None)
        .await
        .unwrap();
    assert_eq!(
        notification_destinations(&alerts),
        BTreeSet::from(["composite-destination".into()])
    );
}

async fn persist_composite(a: &Alert, destinations: Vec<String>) {
    use sea_orm::IntoActiveModel;
    let definition = infra::table::entity::alert_composites::Model {
        id: a.get_unique_key(),
        org: a.org_id.clone(),
        folder_id: "default".into(),
        name: a.name.clone(),
        description: None,
        expression: "true".into(),
        warning_counts_as_firing: true,
        stale_child_policy: 0,
        destinations: serde_json::to_value(destinations).unwrap(),
        template: None,
        context_attributes: None,
        enabled: true,
        silence_seconds: 0,
        creates_incident: true,
        workflows: serde_json::json!([]),
        priority: None,
        tags: None,
        owner: None,
        last_edited_by: None,
        updated_at: None,
        evaluation_generation: 0,
        pending_period_sec: 0,
    };
    definition
        .into_active_model()
        .insert(infra::db::get_orm_client_rw().await)
        .await
        .unwrap();
}

fn isolated_http_test<F: std::future::Future<Output = ()>>(
    path: &str,
    envs: &[(&str, &str)],
    task: impl FnOnce() -> F,
) {
    if std::env::var_os("O2_SSRF_ISOLATED_TEST").is_some() {
        crate::ssrf_test_support::isolated(path, envs, task);
        return;
    }
    let directory = std::env::temp_dir().join(format!(
        "oss-incidents-{}",
        svix_ksuid::Ksuid::new(None, None)
    ));
    let mut isolated_envs = envs.to_vec();
    isolated_envs.push(("ZO_DATA_DIR", directory.to_str().unwrap()));
    crate::ssrf_test_support::isolated(path, &isolated_envs, task);
    std::fs::remove_dir_all(directory).unwrap();
}

async fn capture_destination() -> (String, tokio::sync::mpsc::UnboundedReceiver<Value>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut request = Vec::new();
            let mut bytes = [0; 8192];
            loop {
                let count = socket.read(&mut bytes).await.unwrap_or(0);
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&bytes[..count]);
                if let Some(header) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..header]);
                    let length = headers
                        .lines()
                        .filter_map(|line| line.split_once(':'))
                        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if request.len() >= header + 4 + length {
                        let value =
                            serde_json::from_slice(&request[header + 4..header + 4 + length])
                                .unwrap();
                        let _ = sender.send(value);
                        break;
                    }
                }
            }
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        }
    });
    (format!("http://{address}/ok"), receiver)
}

#[test]
fn incidents_oss_failed_firing_and_severity_deliver_after_transport_recovers() {
    isolated_http_test(
        concat!(
            module_path!(),
            "::incidents_oss_failed_firing_and_severity_deliver_after_transport_recovers"
        ),
        &[("ZO_SSRF_ALLOWED_CIDRS", "127.0.0.1/32")],
        || async {
            setup().await;
            let org = format!("oss-delivery-{}", svix_ksuid::Ksuid::new(None, None));
            let mut a = alert(&org, "Retry transport");
            a.destinations = vec!["target".into()];
            common::infra::config::ALERTS.write().await.insert(
                db::alerts::alert::cache_alert_key(&org, &a.get_unique_key()),
                (Default::default(), a.clone()),
            );
            let bad = config::meta::destinations::Destination {
                org_id: org.clone(),
                name: "target".into(),
                module: config::meta::destinations::Module::Pipeline {
                    endpoint: Default::default(),
                },
                ..Default::default()
            };
            common::infra::config::DESTINATIONS.insert(format!("{org}/target"), bad.clone());
            let rows = [Map::new()];
            assert!(
                correlate_alert_to_incident(&a, &rows[0], &rows, 1, None)
                    .await
                    .is_err()
            );
            let (url, mut received) = capture_destination().await;
            let good = config::meta::destinations::Destination {
                org_id: org.clone(),
                name: "target".into(),
                module: config::meta::destinations::Module::Alert {
                    template: None,
                    destination_type: config::meta::destinations::DestinationType::Http(
                        config::meta::destinations::Endpoint {
                            url,
                            ..Default::default()
                        },
                    ),
                },
                ..Default::default()
            };
            common::infra::config::DESTINATIONS.insert(format!("{org}/target"), good.clone());
            let saved = store::list(&org, None, 10, 0).await.unwrap()[0].id.clone();
            let model = require_incident(&org, &saved).await.unwrap();
            assert_eq!(pending_notifications(&model).unwrap().len(), 1);
            let mut context = model.topology_context.clone().unwrap();
            context.as_object_mut().unwrap().insert(
                "existing_metadata".into(),
                serde_json::json!({"keep": true}),
            );
            let mut active: alert_incidents::ActiveModel = model.into();
            active.topology_context = Set(Some(context));
            active
                .update(infra::db::get_orm_client_rw().await)
                .await
                .unwrap();
            let (left, right) = tokio::join!(
                correlate_alert_to_incident(&a, &rows[0], &rows, 2, None),
                correlate_alert_to_incident(&a, &rows[0], &rows, 3, None)
            );
            let outcome = left.unwrap().unwrap();
            assert_eq!(right.unwrap().unwrap().incident_id(), outcome.incident_id());
            let model = require_incident(&org, outcome.incident_id()).await.unwrap();
            assert!(pending_notifications(&model).unwrap().is_empty());
            assert_eq!(
                model.topology_context.unwrap()["existing_metadata"]["keep"],
                true
            );
            let delivered =
                tokio::time::timeout(std::time::Duration::from_secs(2), received.recv())
                    .await
                    .expect("retry must send the pending creation event")
                    .unwrap();
            assert_eq!(delivered["incident"]["event"], "new_incident_created");
            common::infra::config::DESTINATIONS.insert(format!("{org}/target"), bad);
            assert!(
                update_severity(&org, outcome.incident_id(), "P1", "operator")
                    .await
                    .is_err()
            );
            common::infra::config::DESTINATIONS.insert(format!("{org}/target"), good);
            update_severity(&org, outcome.incident_id(), "P1", "operator")
                .await
                .unwrap();
            let delivered =
                tokio::time::timeout(std::time::Duration::from_secs(2), received.recv())
                    .await
                    .expect("same-severity retry must send pending event")
                    .unwrap();
            assert_eq!(delivered["incident"]["event"], "severity_changed");
            assert_eq!(delivered["incident"]["severity"], "P1");
            correlate_alert_to_incident(&a, &rows[0], &rows, 3, None)
                .await
                .unwrap();
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), received.recv())
                    .await
                    .is_err(),
                "successful repeats must stay suppressed"
            );
        },
    );
}

#[test]
fn incidents_oss_composite_join_and_severity_notify_all_related_destinations() {
    isolated_http_test(
        concat!(
            module_path!(),
            "::incidents_oss_composite_join_and_severity_notify_all_related_destinations"
        ),
        &[
            ("ZO_SSRF_ALLOWED_CIDRS", "127.0.0.1/32"),
            ("ZO_OSS_INCIDENTS_GROUPING_FIELDS", "service"),
        ],
        || async {
            setup().await;
            let org = format!(
                "oss-composite-delivery-{}",
                svix_ksuid::Ksuid::new(None, None)
            );
            let mut composite = alert(&org, "Composite");
            composite.destinations = vec!["composite".into()];
            persist_composite(&composite, composite.destinations.clone()).await;
            let mut normal = alert(&org, "Normal");
            normal.destinations = vec!["normal".into(), "composite".into()];
            common::infra::config::ALERTS.write().await.insert(
                db::alerts::alert::cache_alert_key(&org, &normal.get_unique_key()),
                (Default::default(), normal.clone()),
            );
            let (url, mut received) = capture_destination().await;
            for name in ["composite", "normal"] {
                common::infra::config::DESTINATIONS.insert(
                    format!("{org}/{name}"),
                    config::meta::destinations::Destination {
                        org_id: org.clone(),
                        name: name.into(),
                        module: config::meta::destinations::Module::Alert {
                            template: None,
                            destination_type: config::meta::destinations::DestinationType::Http(
                                config::meta::destinations::Endpoint {
                                    url: url.clone(),
                                    ..Default::default()
                                },
                            ),
                        },
                        ..Default::default()
                    },
                );
            }
            let row = serde_json::from_value(serde_json::json!({"service": "api"})).unwrap();
            let rows = [row];
            let first = correlate_alert_to_incident(&composite, &rows[0], &rows, 1, None)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                received.recv().await.unwrap()["incident"]["event"],
                "new_incident_created"
            );
            let second = correlate_alert_to_incident(&normal, &rows[0], &rows, 2, None)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(first.incident_id(), second.incident_id());
            for _ in 0..2 {
                assert_eq!(
                    received.recv().await.unwrap()["incident"]["event"],
                    "new_alert_correlated"
                );
            }
            update_severity(&org, first.incident_id(), "P1", "operator")
                .await
                .unwrap();
            for _ in 0..2 {
                assert_eq!(
                    received.recv().await.unwrap()["incident"]["event"],
                    "severity_changed"
                );
            }
            let detail = get_incident_with_alerts(&org, first.incident_id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(detail.composite_alerts.len(), 1);
            assert_eq!(detail.alerts.len(), 1);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), received.recv())
                    .await
                    .is_err()
            );
        },
    );
}

fn scheduler_regression(path: &str, empty_only: bool) {
    isolated_http_test(
        path,
        &[
            ("ZO_SSRF_ALLOWED_CIDRS", "127.0.0.1/32"),
            ("ZO_OSS_INCIDENTS_AUTO_RESOLVE_TIMEOUT_SECS", "120"),
            ("ZO_OSS_INCIDENTS_GROUPING_FIELDS", "service"),
        ],
        || async {
            use config::meta::{
                alerts::level::{AlertLevel, DeliveryDecision},
                self_reporting::usage::RunOutcome,
            };

            use crate::alerts::scheduler::handlers::{
                correlate_scheduled_incident, scheduled_incident_outcome,
                should_dispatch_after_incident,
            };
            setup().await;
            let org = format!("oss-scheduler-{}", svix_ksuid::Ksuid::new(None, None));
            let (url, mut received) = capture_destination().await;
            common::infra::config::DESTINATIONS.insert(
                format!("{org}/target"),
                config::meta::destinations::Destination {
                    org_id: org.clone(),
                    name: "target".into(),
                    module: config::meta::destinations::Module::Alert {
                        template: None,
                        destination_type: config::meta::destinations::DestinationType::Http(
                            config::meta::destinations::Endpoint {
                                url,
                                ..Default::default()
                            },
                        ),
                    },
                    ..Default::default()
                },
            );
            assert_eq!(
                config::get_config().oss_incidents.auto_resolve_timeout_secs,
                120
            );
            let now = config::utils::time::now_micros();
            let rows = [Map::new()];
            for composite in [false, true].into_iter().filter(|_| !empty_only) {
                let mut a = alert(&org, if composite { "Composite" } else { "Ordinary" });
                a.destinations = vec!["target".into()];
                if composite {
                    persist_composite(&a, a.destinations.clone()).await;
                } else {
                    common::infra::config::ALERTS.write().await.insert(
                        db::alerts::alert::cache_alert_key(&org, &a.get_unique_key()),
                        (Default::default(), a.clone()),
                    );
                }
                let first = correlate_scheduled_incident(
                    &a,
                    Some(&rows),
                    &RunOutcome::Firing,
                    DeliveryDecision::Deliver,
                    now - 180_000_000,
                    Some(AlertLevel::Critical),
                )
                .await
                .unwrap()
                .unwrap();
                assert!(received.recv().await.is_some());
                update_status(&org, first.incident_id(), "acknowledged", "operator")
                    .await
                    .unwrap();
                let suppressed = correlate_scheduled_incident(
                    &a,
                    Some(&rows),
                    &RunOutcome::Firing,
                    DeliveryDecision::SuppressedBySilence,
                    now,
                    Some(AlertLevel::Critical),
                )
                .await
                .unwrap();
                let detail = get_incident_with_alerts(&org, first.incident_id())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    detail.incident.last_alert_at, now,
                    "suppressed firings must refresh activity"
                );
                assert_eq!(detail.triggers.len(), 2);
                assert!(suppressed.is_some());
                assert_eq!(detail.incident.status, IncidentStatus::Acknowledged);
                let quiet = alert(&org, "Quiet control");
                let quiet_incident = correlate_scheduled_incident(
                    &quiet,
                    Some(&rows),
                    &RunOutcome::Firing,
                    DeliveryDecision::SuppressedBySilence,
                    now - 180_000_000,
                    None,
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(
                    resolve_stale().await.unwrap(),
                    1,
                    "only the quiet control may resolve"
                );
                assert_eq!(
                    require_incident(&org, quiet_incident.incident_id())
                        .await
                        .unwrap()
                        .status,
                    "resolved"
                );
                assert_eq!(
                    require_incident(&org, first.incident_id())
                        .await
                        .unwrap()
                        .status,
                    "acknowledged"
                );
                assert!(
                    tokio::time::timeout(std::time::Duration::from_millis(50), received.recv())
                        .await
                        .is_err()
                );
                let events = get_events(&org, first.incident_id()).await.unwrap();
                assert!(events.iter().any(|event| matches!(event.event_type, config::meta::alerts::incidents::IncidentEventType::Alert { last_at, .. } if last_at == now)), "suppressed firings must advance timeline history");
                for outcome in [
                    RunOutcome::Pending,
                    RunOutcome::Normal,
                    RunOutcome::Skipped,
                    RunOutcome::Error,
                ] {
                    assert!(
                        correlate_scheduled_incident(
                            &a,
                            Some(&rows),
                            &outcome,
                            DeliveryDecision::Deliver,
                            now + 1,
                            None
                        )
                        .await
                        .unwrap()
                        .is_none()
                    );
                }
                assert_eq!(
                    get_incident_with_alerts(&org, first.incident_id())
                        .await
                        .unwrap()
                        .unwrap()
                        .triggers
                        .len(),
                    2
                );
            }
            if !empty_only {
                cleanup(&org).await;
                return;
            }
            let mut empty = alert(&org, "Zero rows");
            empty.destinations = vec!["target".into()];
            common::infra::config::ALERTS.write().await.insert(
                db::alerts::alert::cache_alert_key(&org, &empty.get_unique_key()),
                (Default::default(), empty.clone()),
            );
            assert!(
                correlate_scheduled_incident(
                    &empty,
                    None,
                    &RunOutcome::Firing,
                    DeliveryDecision::Deliver,
                    now,
                    None
                )
                .await
                .unwrap()
                .is_none()
            );
            empty.pending_period_sec = 60;
            let mut previous =
                config::meta::alerts::state::AlertState::empty(&empty.get_unique_key(), "");
            previous.last_outcome = Some(RunOutcome::Pending);
            previous.since = Some(now - 30_000_000);
            for prior in [None, Some(&previous)] {
                let pending = scheduled_incident_outcome(&empty, prior, true, now);
                assert_eq!(pending, RunOutcome::Pending);
                assert!(
                    correlate_scheduled_incident(
                        &empty,
                        Some(&[]),
                        &pending,
                        DeliveryDecision::Deliver,
                        now,
                        None
                    )
                    .await
                    .unwrap()
                    .is_none()
                );
            }
            assert_eq!(store::count(&org, None).await.unwrap(), 0);
            previous.since = Some(now - 61_000_000);
            assert_eq!(
                scheduled_incident_outcome(&empty, Some(&previous), true, now),
                RunOutcome::Firing
            );
            assert_eq!(
                scheduled_incident_outcome(&empty, Some(&previous), false, now),
                RunOutcome::Normal
            );
            empty.pending_period_sec = 0;
            let matched = correlate_scheduled_incident(
                &empty,
                Some(&[]),
                &RunOutcome::Firing,
                DeliveryDecision::Deliver,
                now,
                None,
            )
            .await
            .unwrap();
            assert!(matched.is_some(), "Some(empty) is a matched firing");
            let matched = matched.unwrap();
            let detail = get_incident_with_alerts(&org, matched.incident_id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(detail.incident.key_type, KeyType::AlertId);
            assert_eq!(detail.triggers.len(), 1);
            assert!(received.recv().await.is_some());
            assert!(
                !should_dispatch_after_incident(true, false),
                "incident handling suppresses direct delivery"
            );
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), received.recv())
                    .await
                    .is_err()
            );
            let mut suppressed = alert(&org, "Suppressed first firing");
            suppressed.destinations = vec!["target".into()];
            common::infra::config::ALERTS.write().await.insert(
                db::alerts::alert::cache_alert_key(&org, &suppressed.get_unique_key()),
                (Default::default(), suppressed.clone()),
            );
            let queued = correlate_scheduled_incident(
                &suppressed,
                Some(&rows),
                &RunOutcome::Firing,
                DeliveryDecision::SuppressedByWarningPolicy,
                now,
                Some(AlertLevel::Warning),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                pending_notifications(&require_incident(&org, queued.incident_id()).await.unwrap())
                    .unwrap()
                    .len(),
                1
            );
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), received.recv())
                    .await
                    .is_err(),
                "suppressed creation must not send queued notifications"
            );
            correlate_scheduled_incident(
                &suppressed,
                Some(&rows),
                &RunOutcome::Firing,
                DeliveryDecision::SuppressedBySilence,
                now + 1,
                Some(AlertLevel::Warning),
            )
            .await
            .unwrap();
            assert_eq!(
                pending_notifications(&require_incident(&org, queued.incident_id()).await.unwrap())
                    .unwrap()
                    .len(),
                1
            );
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), received.recv())
                    .await
                    .is_err(),
                "suppressed repeat must not drain queued notifications"
            );
            correlate_scheduled_incident(
                &suppressed,
                Some(&rows),
                &RunOutcome::Firing,
                DeliveryDecision::Deliver,
                now + 2,
                Some(AlertLevel::Critical),
            )
            .await
            .unwrap();
            assert!(received.recv().await.is_some());
            assert!(
                pending_notifications(&require_incident(&org, queued.incident_id()).await.unwrap())
                    .unwrap()
                    .is_empty()
            );
            empty.creates_incident = false;
            assert!(
                correlate_scheduled_incident(
                    &empty,
                    Some(&rows),
                    &RunOutcome::Firing,
                    DeliveryDecision::Deliver,
                    now,
                    None
                )
                .await
                .unwrap()
                .is_none()
            );
            cleanup(&org).await;
        },
    );
}

#[test]
fn incidents_oss_scheduler_suppressed_firings_prevent_stale_resolution() {
    scheduler_regression(
        concat!(
            module_path!(),
            "::incidents_oss_scheduler_suppressed_firings_prevent_stale_resolution"
        ),
        false,
    );
}

#[test]
fn incidents_oss_scheduler_empty_match_creates_incident_but_nonmatch_does_not() {
    scheduler_regression(
        concat!(
            module_path!(),
            "::incidents_oss_scheduler_empty_match_creates_incident_but_nonmatch_does_not"
        ),
        true,
    );
}
