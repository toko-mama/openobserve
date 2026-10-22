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

#[path = "incidents_oss_grouping.rs"]
mod grouping;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{Context, anyhow, bail};
use config::{
    meta::alerts::{
        alert::Alert,
        incidents::{
            AlertKind, CompositeAlertSummary, CorrelationReason, Incident, IncidentAlert,
            IncidentCorrelationOutcome, IncidentEvent, IncidentSeverity, IncidentStats,
            IncidentStatus, IncidentWithAlerts, KeyType,
        },
        recovery::RecoveryEvent,
    },
    utils::json::{Map, Value},
};
use infra::table::{
    alert_incidents as store,
    entity::{
        alert_incident_alerts,
        alert_incidents::{self, Model},
    },
    incident_events,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter,
    QuerySelect, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use svix_ksuid::KsuidLike;
use tokio::sync::Mutex;

use self::grouping::{Grouping, grouping};

// SQLite cannot lock a missing correlation row; single-node mutations share this lock.
static MUTATIONS: Mutex<()> = Mutex::const_new(());

#[derive(Clone, Serialize, Deserialize)]
struct PendingNotification {
    id: String,
    payload: Value,
}

pub async fn correlate_alert_to_incident(
    alert: &Alert,
    result_row: &Map<String, Value>,
    notify_rows: &[Map<String, Value>],
    triggered_at: i64,
    _eval_level: Option<config::meta::alerts::level::AlertLevel>,
) -> Result<Option<IncidentCorrelationOutcome>, anyhow::Error> {
    let cfg = config::get_config();
    if !cfg.oss_incidents.enabled || !alert.creates_incident {
        return Ok(None);
    }
    let outcome = correlate_firing(
        alert,
        result_row,
        triggered_at,
        &cfg.oss_incidents.grouping_fields(),
    )
    .await?;
    if !notify_rows.is_empty() {
        deliver_pending(&alert.org_id, outcome.incident_id(), Some(alert)).await?;
    }
    Ok(Some(outcome))
}

pub async fn list_incidents(
    org_id: &str,
    status: Option<&str>,
    limit: u64,
    offset: u64,
) -> Result<(Vec<Incident>, u64), anyhow::Error> {
    validate_pagination(limit, offset)?;
    let status = status.map(parse_status).transpose()?.map(|s| s.to_string());
    let count = store::count(org_id, status.as_deref()).await?;
    let incidents = store::list(org_id, status.as_deref(), limit, offset).await?;
    Ok((
        incidents.into_iter().map(model_to_incident).collect(),
        count,
    ))
}

pub async fn get_incident_with_alerts(
    org_id: &str,
    incident_id: &str,
) -> Result<Option<IncidentWithAlerts>, anyhow::Error> {
    let Some(incident) = store::get(org_id, incident_id).await? else {
        return Ok(None);
    };
    let links = store::get_incident_alerts(incident_id).await?;
    let mut incident = model_to_incident(incident);
    incident.alert_count = links.len() as i32;
    let triggers = links
        .into_iter()
        .map(|link| IncidentAlert {
            incident_id: link.incident_id,
            alert_id: link.alert_id,
            alert_name: link.alert_name,
            alert_kind: AlertKind::from_stored(&link.alert_kind),
            alert_fired_at: link.alert_fired_at,
            correlation_reason: link
                .correlation_reason
                .as_deref()
                .and_then(|s| CorrelationReason::try_from(s).ok())
                .unwrap_or(CorrelationReason::AlertId),
            created_at: link.created_at,
            source_url: None,
            labels: None,
            detected_source: None,
        })
        .collect();
    let composite_alerts = related_composites(org_id, incident_id).await?;
    let composite_ids: BTreeSet<_> = composite_alerts
        .iter()
        .map(|item| item.id.as_str())
        .collect();
    let alerts = related_alerts(org_id, incident_id, None)
        .await?
        .into_iter()
        .filter(|alert| !composite_ids.contains(alert.get_unique_key().as_str()))
        .collect();
    Ok(Some(IncidentWithAlerts {
        incident,
        triggers,
        alerts,
        composite_alerts,
    }))
}

pub async fn update_status(
    org_id: &str,
    incident_id: &str,
    status: &str,
    user_id: &str,
) -> Result<Incident, anyhow::Error> {
    let status = parse_status(status)?;
    let _guard = MUTATIONS.lock().await;
    let current = require_incident(org_id, incident_id).await?;
    if current.status == status.to_string() {
        return Ok(model_to_incident(current));
    }
    if status == IncidentStatus::Acknowledged && current.status != "open" {
        bail!("Only open incidents can be acknowledged");
    }
    let event = match status {
        IncidentStatus::Open => IncidentEvent::reopened(user_id, "Manually reopened"),
        IncidentStatus::Acknowledged => IncidentEvent::acknowledged(user_id),
        IncidentStatus::Resolved => IncidentEvent::resolved(Some(user_id.to_owned())),
    };
    let txn = infra::db::get_orm_client_rw().await.begin().await?;
    let updated = change_status(&txn, current, status, Some(user_id)).await?;
    incident_events::append_in_transaction(&txn, org_id, incident_id, event).await?;
    txn.commit().await?;
    Ok(model_to_incident(updated))
}

pub async fn update_title(
    org_id: &str,
    incident_id: &str,
    title: &str,
    user_id: &str,
) -> Result<Incident, anyhow::Error> {
    let title = title.trim();
    if title.is_empty() || title.chars().count() > 500 {
        bail!("Title must contain between 1 and 500 characters");
    }
    let _guard = MUTATIONS.lock().await;
    let current = require_incident(org_id, incident_id).await?;
    if current.title.as_deref() == Some(title) {
        return Ok(model_to_incident(current));
    }
    let event =
        IncidentEvent::title_changed(current.title.clone().unwrap_or_default(), title, user_id);
    let txn = infra::db::get_orm_client_rw().await.begin().await?;
    let mut active: alert_incidents::ActiveModel = current.into();
    active.title = Set(Some(title.to_owned()));
    active.updated_at = Set(config::utils::time::now_micros());
    let updated = active.update(&txn).await?;
    incident_events::append_in_transaction(&txn, org_id, incident_id, event).await?;
    txn.commit().await?;
    Ok(model_to_incident(updated))
}

pub async fn update_severity(
    org_id: &str,
    incident_id: &str,
    severity: &str,
    user_id: &str,
) -> Result<Incident, anyhow::Error> {
    let to: IncidentSeverity = severity.parse().map_err(|e| anyhow!("{e}"))?;
    {
        let _guard = MUTATIONS.lock().await;
        let current = require_incident(org_id, incident_id).await?;
        let from = current.severity.parse().unwrap_or_default();
        if from != to {
            let related = related_alerts(org_id, incident_id, None).await?;
            let txn = infra::db::get_orm_client_rw().await.begin().await?;
            let mut active: alert_incidents::ActiveModel = current.into();
            active.severity = Set(to.to_string());
            active.updated_at = Set(config::utils::time::now_micros());
            let updated = active.update(&txn).await?;
            enqueue_notification(
                &txn,
                updated,
                "severity_changed",
                config::utils::time::now_micros(),
                related.first(),
            )
            .await?;
            incident_events::append_in_transaction(
                &txn,
                org_id,
                incident_id,
                IncidentEvent::severity_override(from, to, user_id),
            )
            .await?;
            txn.commit().await?;
        }
    }
    deliver_pending(org_id, incident_id, None).await?;
    Ok(model_to_incident(
        require_incident(org_id, incident_id).await?,
    ))
}

pub async fn get_events(
    org_id: &str,
    incident_id: &str,
) -> Result<Vec<IncidentEvent>, anyhow::Error> {
    require_incident(org_id, incident_id).await?;
    Ok(incident_events::get(org_id, incident_id).await?)
}

pub async fn add_comment(
    org_id: &str,
    incident_id: &str,
    user_id: &str,
    comment: &str,
) -> Result<(), anyhow::Error> {
    let comment = comment.trim();
    if comment.is_empty() || comment.chars().count() > 10_000 {
        bail!("Comment must contain between 1 and 10000 characters");
    }
    let _guard = MUTATIONS.lock().await;
    require_incident(org_id, incident_id).await?;
    Ok(incident_events::append(
        org_id,
        incident_id,
        IncidentEvent::comment(user_id, comment),
    )
    .await?)
}

pub async fn get_incident_stats(org_id: &str) -> Result<IncidentStats, anyhow::Error> {
    let mut stats = IncidentStats {
        total_incidents: 0,
        open_incidents: 0,
        acknowledged_incidents: 0,
        resolved_incidents: 0,
        by_severity: HashMap::new(),
        by_service: HashMap::new(),
        mttr_minutes: None,
        alerts_per_incident_avg: 0.0,
    };
    let mut offset = 0;
    let mut resolution_minutes = 0.0;
    let mut resolutions = 0;
    loop {
        let page = store::list(org_id, None, 500, offset).await?;
        let full = page.len() == 500;
        for incident in page {
            stats.total_incidents += 1;
            match incident.status.as_str() {
                "open" => stats.open_incidents += 1,
                "acknowledged" => stats.acknowledged_incidents += 1,
                "resolved" => stats.resolved_incidents += 1,
                _ => {}
            }
            *stats.by_severity.entry(incident.severity).or_default() += 1;
            if let Some(service) = incident.group_values.get("service").and_then(Value::as_str) {
                *stats.by_service.entry(service.to_owned()).or_default() += 1;
            }
            stats.alerts_per_incident_avg += f64::from(incident.alert_count);
            if incident.status == "resolved"
                && let Some(at) = incident.resolved_at
            {
                resolution_minutes +=
                    at.saturating_sub(incident.first_alert_at).max(0) as f64 / 60_000_000.0;
                resolutions += 1;
            }
        }
        if !full {
            break;
        }
        offset += 500;
    }
    if resolutions > 0 {
        stats.mttr_minutes = Some(resolution_minutes / f64::from(resolutions));
    }
    if stats.total_incidents > 0 {
        stats.alerts_per_incident_avg /= stats.total_incidents as f64;
    }
    Ok(stats)
}

pub async fn resolve_alert_firing(event: &RecoveryEvent) -> Result<(), anyhow::Error> {
    let Some(id) = event.incident_id.as_deref() else {
        return Ok(());
    };
    let _guard = MUTATIONS.lock().await;
    let current = require_incident(&event.org_id, id).await?;
    let txn = infra::db::get_orm_client_rw().await.begin().await?;
    alert_incident_alerts::Entity::update_many()
        .col_expr(
            alert_incident_alerts::Column::ResolvedAt,
            sea_orm::sea_query::Expr::value(Some(event.recovered_at)),
        )
        .filter(alert_incident_alerts::Column::IncidentId.eq(id))
        .filter(alert_incident_alerts::Column::AlertId.eq(&event.alert_id))
        .filter(alert_incident_alerts::Column::AlertFiredAt.lte(event.recovered_at))
        .filter(alert_incident_alerts::Column::ResolvedAt.is_null())
        .exec(&txn)
        .await?;
    let links = alert_incident_alerts::Entity::find()
        .filter(alert_incident_alerts::Column::IncidentId.eq(id))
        .all(&txn)
        .await?;
    if current.status != "resolved"
        && current.acknowledged_by.is_none()
        && current.assigned_to.is_none()
        && !links.is_empty()
        && links.iter().all(|link| link.resolved_at.is_some())
    {
        change_status(&txn, current, IncidentStatus::Resolved, None).await?;
        incident_events::append_in_transaction(
            &txn,
            &event.org_id,
            id,
            IncidentEvent::resolved(None),
        )
        .await?;
    }
    txn.commit().await?;
    Ok(())
}

pub async fn resolve_stale() -> Result<u64, anyhow::Error> {
    let cfg = config::get_config();
    let timeout = cfg.oss_incidents.auto_resolve_timeout_secs;
    if !cfg.oss_incidents.enabled || timeout == 0 {
        return Ok(0);
    }
    let threshold = i64::try_from(timeout)
        .ok()
        .and_then(|n| n.checked_mul(1_000_000))
        .ok_or_else(|| anyhow!("Auto-resolution timeout is too large"))?;
    let _guard = MUTATIONS.lock().await;
    let mut count = 0;
    loop {
        let txn = infra::db::get_orm_client_rw().await.begin().await?;
        let stale = alert_incidents::Entity::find()
            .filter(alert_incidents::Column::Status.ne("resolved"))
            .filter(
                alert_incidents::Column::LastAlertAt
                    .lt(config::utils::time::now_micros().saturating_sub(threshold)),
            )
            .limit(500)
            .all(&txn)
            .await?;
        let full = stale.len() == 500;
        for incident in stale {
            let org = incident.org_id.clone();
            let id = incident.id.clone();
            change_status(&txn, incident, IncidentStatus::Resolved, None).await?;
            incident_events::append_in_transaction(&txn, &org, &id, IncidentEvent::resolved(None))
                .await?;
            count += 1;
        }
        txn.commit().await?;
        if !full {
            break;
        }
    }
    Ok(count)
}

async fn correlate_firing(
    alert: &Alert,
    result_row: &Map<String, Value>,
    triggered_at: i64,
    fields: &[String],
) -> Result<IncidentCorrelationOutcome, anyhow::Error> {
    let alert_id = alert.get_unique_key();
    if alert_id.is_empty() {
        bail!("Incident correlation requires a persisted alert ID");
    }
    let labels = result_row
        .iter()
        .filter_map(|(key, value)| {
            let value = match value {
                Value::String(s) => s.clone(),
                Value::Bool(_) | Value::Number(_) => value.to_string(),
                _ => return None,
            };
            Some((key.clone(), value))
        })
        .collect::<BTreeMap<_, _>>();
    let group = grouping(&alert_id, fields, &labels);
    let key_type = if group.alert_fallback {
        "AlertId"
    } else {
        "Primary"
    };
    let key = group.key(&alert.org_id);
    let values = serde_json::to_value(&group.values)?;
    let _guard = MUTATIONS.lock().await;
    let candidates = store::find_open_incidents_filtered(&alert.org_id, None, None).await?;
    let current = candidates.into_iter().find(|incident| {
        if incident.key_type != key_type {
            return false;
        }
        let Ok(values) = serde_json::from_value(incident.group_values.clone()) else {
            return false;
        };
        Grouping {
            values,
            alert_fallback: group.alert_fallback,
        }
        .key(&alert.org_id)
            == key
    });
    let txn = infra::db::get_orm_client_rw().await.begin().await?;
    let (incident, created) = match current {
        Some(current) => (current, false),
        None => {
            let severity = alert
                .priority
                .map(|priority| match priority.as_str() {
                    "P1" => "P1",
                    "P2" => "P2",
                    "P4" | "P5" => "P4",
                    _ => "P3",
                })
                .unwrap_or("P3");
            let created = store::create_in_transaction(
                &txn,
                &alert.org_id,
                severity,
                values,
                key_type,
                triggered_at,
                Some(alert.name.clone()),
            )
            .await?;
            incident_events::append_in_transaction(
                &txn,
                &alert.org_id,
                &created.id,
                IncidentEvent::created(),
            )
            .await?;
            (created, true)
        }
    };
    let links = alert_incident_alerts::Entity::find()
        .filter(alert_incident_alerts::Column::IncidentId.eq(&incident.id))
        .all(&txn)
        .await?;
    let is_duplicate = links
        .iter()
        .any(|link| link.alert_id == alert_id && link.alert_fired_at == triggered_at);
    let new_alert = if is_duplicate {
        false
    } else {
        store::add_alert_in_transaction(
            &txn,
            &incident.id,
            &alert_id,
            &alert.name,
            "internal",
            triggered_at,
            if group.alert_fallback {
                "alert_id"
            } else {
                "primary_match"
            },
        )
        .await?
    };
    if !is_duplicate {
        incident_events::record_alert_in_transaction(
            &txn,
            &alert.org_id,
            &incident.id,
            &alert_id,
            &alert.name,
            triggered_at,
        )
        .await?;
    }
    let service_name = group.values.get("service").cloned().unwrap_or_default();
    let outcome = if created {
        IncidentCorrelationOutcome::NewIncidentCreated {
            incident_id: incident.id,
            service_name,
        }
    } else if new_alert {
        IncidentCorrelationOutcome::NewAlertTypeJoined {
            incident_id: incident.id,
            service_name,
        }
    } else {
        IncidentCorrelationOutcome::ExistingAlertRepeated {
            incident_id: incident.id,
            service_name,
        }
    };
    if let Some(event) = notification_event(&outcome) {
        let updated = alert_incidents::Entity::find_by_id(outcome.incident_id())
            .one(&txn)
            .await?
            .ok_or_else(|| anyhow!("Incident not found"))?;
        enqueue_notification(&txn, updated, event, triggered_at, Some(alert)).await?;
    }
    txn.commit().await?;
    Ok(outcome)
}

fn notification_event(outcome: &IncidentCorrelationOutcome) -> Option<&'static str> {
    match outcome {
        IncidentCorrelationOutcome::NewIncidentCreated { .. } => Some("new_incident_created"),
        IncidentCorrelationOutcome::NewAlertTypeJoined { .. } => Some("new_alert_correlated"),
        IncidentCorrelationOutcome::SeverityEscalated { .. } => Some("severity_changed"),
        IncidentCorrelationOutcome::ExistingAlertRepeated { .. } => None,
    }
}

async fn require_incident(org_id: &str, incident_id: &str) -> Result<Model, anyhow::Error> {
    store::get(org_id, incident_id)
        .await?
        .ok_or_else(|| anyhow!("Incident not found"))
}

fn parse_status(status: &str) -> Result<IncidentStatus, anyhow::Error> {
    status.parse().map_err(|e| anyhow!("{e}"))
}

fn validate_pagination(limit: u64, offset: u64) -> Result<(), anyhow::Error> {
    if !(1..=500).contains(&limit) || offset > i64::MAX as u64 {
        bail!("Limit must be between 1 and 500 and offset must fit a signed integer");
    }
    Ok(())
}

async fn change_status(
    txn: &DatabaseTransaction,
    current: Model,
    status: IncidentStatus,
    actor: Option<&str>,
) -> Result<Model, anyhow::Error> {
    let now = config::utils::time::now_micros();
    let mut active: infra::table::entity::alert_incidents::ActiveModel = current.into();
    active.status = Set(status.to_string());
    active.updated_at = Set(now);
    active.resolved_at = Set((status == IncidentStatus::Resolved).then_some(now));
    if status == IncidentStatus::Open {
        active.acknowledged_by = Set(None);
        active.acknowledged_at = Set(None);
    } else if status == IncidentStatus::Acknowledged {
        active.acknowledged_by = Set(actor.map(str::to_owned));
        active.acknowledged_at = Set(Some(now));
    }
    Ok(active.update(txn).await?)
}

async fn related_alerts(
    org_id: &str,
    incident_id: &str,
    current: Option<&Alert>,
) -> Result<Vec<Alert>, anyhow::Error> {
    let mut alerts = BTreeMap::new();
    if let Some(alert) = current {
        alerts.insert(alert.get_unique_key(), alert.clone());
    }
    for link in store::get_incident_alerts(incident_id).await? {
        if alerts.contains_key(&link.alert_id) {
            continue;
        }
        if let Some((_, alert)) =
            crate::db::alerts::alert::get_alert_from_cache(org_id, &link.alert_id).await
        {
            alerts.insert(link.alert_id, alert);
        } else if let Some(composite) =
            super::composite::get_composite(org_id, &link.alert_id).await?
        {
            alerts.insert(
                link.alert_id,
                super::composite::notification_alert(&composite.definition),
            );
        } else if let Ok(id) = link.alert_id.parse() {
            match super::alert::get_by_id_db(org_id, id).await {
                Ok(alert) => {
                    alerts.insert(link.alert_id, alert);
                }
                Err(super::alert::AlertError::AlertNotFound) => {}
                Err(error) => return Err(anyhow!("{error}")),
            }
        }
    }
    Ok(alerts.into_values().collect())
}

async fn related_composites(
    org_id: &str,
    incident_id: &str,
) -> Result<Vec<CompositeAlertSummary>, anyhow::Error> {
    let ids: BTreeSet<_> = store::get_incident_alerts(incident_id)
        .await?
        .into_iter()
        .map(|link| link.alert_id)
        .collect();
    let mut result = Vec::new();
    for id in ids {
        if let Some(item) = super::composite::get_composite(org_id, &id).await? {
            result.push(CompositeAlertSummary {
                id: item.definition.id,
                name: item.definition.name,
                alert_type: "composite".into(),
                enabled: item.definition.enabled,
                folder_id: item.definition.folder_id,
            });
        }
    }
    Ok(result)
}

fn pending_notifications(model: &Model) -> Result<Vec<PendingNotification>, anyhow::Error> {
    model
        .topology_context
        .as_ref()
        .and_then(|context| context.get("oss_pending_notifications"))
        .map(|value| serde_json::from_value(value.clone()).map_err(anyhow::Error::from))
        .unwrap_or_else(|| Ok(Vec::new()))
}

fn with_pending(
    model: Model,
    pending: &[PendingNotification],
) -> Result<alert_incidents::ActiveModel, anyhow::Error> {
    let mut context = model
        .topology_context
        .clone()
        .unwrap_or_else(|| serde_json::json!({}));
    let object = context
        .as_object_mut()
        .ok_or_else(|| anyhow!("Incident topology context must be an object"))?;
    object.insert(
        "oss_pending_notifications".into(),
        serde_json::to_value(pending)?,
    );
    let mut active: alert_incidents::ActiveModel = model.into();
    active.topology_context = Set(Some(context));
    Ok(active)
}

async fn enqueue_notification(
    txn: &DatabaseTransaction,
    model: Model,
    event: &str,
    triggered_at: i64,
    alert: Option<&Alert>,
) -> Result<(), anyhow::Error> {
    let mut pending = pending_notifications(&model)?;
    pending.push(PendingNotification {
        id: svix_ksuid::Ksuid::new(None, None).to_string(),
        payload: notification_payload(&model, event, triggered_at, alert),
    });
    with_pending(model, &pending)?.update(txn).await?;
    Ok(())
}

async fn deliver_pending(
    org_id: &str,
    incident_id: &str,
    current: Option<&Alert>,
) -> Result<(), anyhow::Error> {
    // Hold the mutation lock through delivery so competing callers cannot drain one event twice.
    let _guard = MUTATIONS.lock().await;
    let mut model = require_incident(org_id, incident_id).await?;
    let mut pending = pending_notifications(&model)?;
    if pending.is_empty() {
        return Ok(());
    }
    let alerts = related_alerts(org_id, incident_id, current).await?;
    let destinations = notification_destinations(&alerts);
    while let Some(next) = pending.first() {
        dispatch_payload(org_id, &next.payload, &destinations).await?;
        pending.remove(0);
        model = with_pending(model, &pending)?
            .update(infra::db::get_orm_client_rw().await)
            .await?;
    }
    Ok(())
}

async fn dispatch_payload(
    org_id: &str,
    payload: &Value,
    destinations: &BTreeSet<String>,
) -> Result<(), anyhow::Error> {
    let event = payload["incident"]["event"].as_str().unwrap_or_default();
    let title = payload["incident"]["title"].as_str().unwrap_or_default();
    let subject = format!("[{event}] {title}");
    let body = payload.to_string();
    let mut errors = Vec::new();
    for name in destinations {
        let result = async {
            let destination = crate::db::alerts::destinations::get(org_id, name).await?;
            let config::meta::destinations::Module::Alert {
                destination_type, ..
            } = destination.module
            else {
                bail!("Not an alert destination");
            };
            super::alert::dispatch_notification(&destination_type, &subject, body.clone()).await?;
            Ok::<_, anyhow::Error>(())
        }
        .await
        .with_context(|| format!("Incident destination {name}"));
        if let Err(error) = result {
            errors.push(format!("{error:#}"));
        }
    }
    if !errors.is_empty() {
        bail!("Incident notification failed: {}", errors.join("; "));
    }
    Ok(())
}

fn notification_destinations(alerts: &[Alert]) -> BTreeSet<String> {
    alerts
        .iter()
        .flat_map(|alert| alert.destinations.iter().cloned())
        .collect()
}

fn notification_payload(
    incident: &Model,
    event: &str,
    triggered_at: i64,
    alert: Option<&Alert>,
) -> Value {
    let alert_block = alert.map(|alert| {
        serde_json::json!({
            "name": alert.name,
            "stream": {"name": alert.stream_name, "type": alert.stream_type.to_string()},
        })
    });
    let time = chrono::DateTime::from_timestamp_micros(triggered_at)
        .map(|at| at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default();
    serde_json::json!({"incident": {
        "id": incident.id,
        "title": incident.title.as_deref().unwrap_or_default(),
        "event": event,
        "service": incident.group_values.get("service").and_then(Value::as_str).unwrap_or_default(),
        "severity": incident.severity,
        "alert": alert_block,
        "time": time,
        "url": format!("{}/web/alerts/incidents/{}?org_identifier={}", config::get_config().common.web_url, incident.id, incident.org_id),
    }})
}

fn model_to_incident(model: Model) -> Incident {
    Incident {
        id: model.id,
        org_id: model.org_id,
        status: model.status.parse().unwrap_or_default(),
        severity: model.severity.parse().unwrap_or_default(),
        first_alert_at: model.first_alert_at,
        last_alert_at: model.last_alert_at,
        resolved_at: model.resolved_at,
        alert_count: model.alert_count,
        title: model.title,
        assigned_to: model.assigned_to,
        acknowledged_by: model.acknowledged_by,
        acknowledged_at: model.acknowledged_at,
        created_at: model.created_at,
        updated_at: model.updated_at,
        group_values: model.group_values,
        key_type: KeyType::from_stored(&model.key_type),
        topology_context: None,
    }
}

#[cfg(test)]
#[path = "incidents_oss_tests.rs"]
mod tests;
