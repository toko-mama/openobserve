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

use config::{
    meta::alerts::incidents::{ErrorTracking, IncidentEvent, TraceErrorReference},
    utils::json::{Map, Value},
};
use infra::table::{entity::alert_incidents, incident_events};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAX_RECENT_SPANS: usize = 256;

pub struct TraceErrorOccurrence {
    metadata: ErrorTracking,
    fingerprint: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Deduplication {
    recent_spans: Vec<String>,
}

pub fn extract_trace_errors(
    stream_name: &str,
    timestamp: i64,
    record: &Map<String, Value>,
) -> Vec<TraceErrorOccurrence> {
    let events = record.get("events").and_then(|value| match value {
        Value::String(text) => serde_json::from_str::<Value>(text).ok(),
        Value::Array(_) => Some(value.clone()),
        _ => None,
    });
    let exceptions = events
        .as_ref()
        .and_then(Value::as_array)
        .map(|events| {
            events
                .iter()
                .filter(|event| event.get("name").and_then(Value::as_str) == Some("exception"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if exceptions.is_empty() {
        return extract_occurrence(stream_name, timestamp, record, None)
            .into_iter()
            .collect();
    }
    exceptions
        .into_iter()
        .filter_map(|event| extract_occurrence(stream_name, timestamp, record, Some(event)))
        .collect()
}

fn extract_occurrence(
    stream_name: &str,
    timestamp: i64,
    record: &Map<String, Value>,
    exception: Option<&Value>,
) -> Option<TraceErrorOccurrence> {
    let status = text(record, &["span_status", "status_code"]);
    if exception.is_none() && !status.eq_ignore_ascii_case("ERROR") && status != "2" {
        return None;
    }
    let attributes = exception.and_then(|event| {
        event
            .get("attributes")
            .and_then(Value::as_object)
            .or_else(|| event.as_object())
    });
    let get = |keys: &[&str]| {
        attributes
            .map(|attrs| text(attrs, keys))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| text(record, keys))
    };
    let service = text(record, &["service_name", "service.name"]);
    let operation = text(record, &["operation_name", "name"]);
    let exception_type = get(&[
        "exception.type",
        "exception_type",
        "error.type",
        "error_type",
    ]);
    let stacktrace = get(&["exception.stacktrace", "exception_stacktrace"]);
    let message = get(&["exception.message", "exception_message", "status_message"]);
    let trace_id = text(record, &["trace_id"]);
    let span_id = text(record, &["span_id"]);
    if trace_id.is_empty() || span_id.is_empty() {
        return None;
    }
    let stack = normalize_stack(&stacktrace);
    let identity = if stack.is_empty() {
        operation.clone()
    } else {
        stack
    };
    let fingerprint = hash(&serde_json::to_string(&(&service, &exception_type, identity)).ok()?);
    Some(TraceErrorOccurrence {
        fingerprint,
        metadata: ErrorTracking {
            service,
            exception_type,
            message,
            stacktrace,
            operation,
            occurrence_count: 1,
            first_seen: timestamp,
            last_seen: timestamp,
            latest_trace: TraceErrorReference {
                trace_id,
                span_id,
                stream_name: stream_name.to_owned(),
                timestamp,
            },
        },
    })
}

pub async fn record_trace_errors(
    org_id: &str,
    errors: Vec<TraceErrorOccurrence>,
) -> anyhow::Result<()> {
    let cfg = config::get_config();
    if !cfg.oss_incidents.enabled || !cfg.oss_incidents.trace_errors_enabled || errors.is_empty() {
        return Ok(());
    }
    let _guard = super::MUTATIONS.lock().await;
    let txn = infra::db::get_orm_client_rw().await.begin().await?;
    for occurrence in errors {
        persist(&txn, org_id, occurrence).await?;
    }
    txn.commit().await?;
    Ok(())
}

async fn persist(
    txn: &sea_orm::DatabaseTransaction,
    org_id: &str,
    occurrence: TraceErrorOccurrence,
) -> anyhow::Result<()> {
    let id = hash(&format!("trace-error:{org_id}:{}", occurrence.fingerprint))[..27].to_owned();
    let current = alert_incidents::Entity::find_by_id(&id)
        .filter(alert_incidents::Column::OrgId.eq(org_id))
        .one(txn)
        .await?;
    let creating = current.is_none();
    let mut context = current
        .as_ref()
        .and_then(|row| row.topology_context.clone())
        .unwrap_or_else(|| serde_json::json!({}));
    let mut metadata = occurrence.metadata;
    let incoming_timestamp = metadata.last_seen;
    let mut dedup = current
        .as_ref()
        .and_then(|row| row.topology_context.as_ref())
        .and_then(|v| v.get("trace_error_dedup"))
        .and_then(|v| serde_json::from_value::<Deduplication>(v.clone()).ok())
        .unwrap_or_default();
    let span_key = hash(&format!(
        "{}:{}",
        metadata.latest_trace.trace_id, metadata.latest_trace.span_id
    ));
    if let Some(previous) = context
        .get("error_tracking")
        .and_then(|value| serde_json::from_value::<ErrorTracking>(value.clone()).ok())
    {
        let previous_key = hash(&format!(
            "{}:{}",
            previous.latest_trace.trace_id, previous.latest_trace.span_id
        ));
        infra::table::incident_trace_occurrences::insert(
            txn,
            org_id,
            &id,
            &previous_key,
            &previous.latest_trace,
        )
        .await?;
    }
    let inserted = infra::table::incident_trace_occurrences::insert(
        txn,
        org_id,
        &id,
        &span_key,
        &metadata.latest_trace,
    )
    .await?;
    if !inserted {
        return Ok(());
    }
    if dedup.recent_spans.contains(&span_key) {
        return Ok(());
    }
    dedup.recent_spans.push(span_key);
    if dedup.recent_spans.len() > MAX_RECENT_SPANS {
        dedup.recent_spans.remove(0);
    }
    let now = config::utils::time::now_micros();
    let mut active = if let Some(row) = current {
        if let Some(previous) = row
            .topology_context
            .as_ref()
            .and_then(|v| v.get("error_tracking"))
            .and_then(|v| serde_json::from_value::<ErrorTracking>(v.clone()).ok())
        {
            metadata.occurrence_count = previous.occurrence_count.saturating_add(1);
            metadata.first_seen = previous.first_seen.min(metadata.first_seen);
            if previous.last_seen > metadata.last_seen {
                let count = metadata.occurrence_count;
                let first_seen = metadata.first_seen;
                metadata = previous;
                metadata.occurrence_count = count;
                metadata.first_seen = first_seen;
            }
        }
        let resolved =
            row.status == "resolved" && row.resolved_at.is_none_or(|at| incoming_timestamp > at);
        let mut active: alert_incidents::ActiveModel = row.into();
        if resolved {
            active.status = Set("open".to_owned());
            active.resolved_at = Set(None);
            active.acknowledged_by = Set(None);
            active.acknowledged_at = Set(None);
            incident_events::append_in_transaction(
                txn,
                org_id,
                &id,
                IncidentEvent::reopened("system", "Trace error recurred"),
            )
            .await?;
        }
        active
    } else {
        alert_incidents::ActiveModel {
            id: Set(id.clone()),
            org_id: Set(org_id.to_owned()),
            status: Set("open".to_owned()),
            severity: Set("P3".to_owned()),
            group_values: Set(serde_json::json!({"service": metadata.service})),
            key_type: Set("TraceError".to_owned()),
            title: Set(Some(
                format!(
                    "{}: {}",
                    metadata.service,
                    if metadata.exception_type.is_empty() {
                        &metadata.operation
                    } else {
                        &metadata.exception_type
                    }
                )
                .chars()
                .take(255)
                .collect(),
            )),
            first_alert_at: Set(metadata.first_seen),
            last_alert_at: Set(metadata.last_seen),
            resolved_at: Set(None),
            alert_count: Set(0),
            assigned_to: Set(None),
            acknowledged_by: Set(None),
            acknowledged_at: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
            topology_context: Set(None),
        }
    };
    active.first_alert_at = Set(metadata.first_seen);
    active.last_alert_at = Set(metadata.last_seen);
    active.updated_at = Set(now);
    context["error_tracking"] = serde_json::to_value(metadata)?;
    context["trace_error_dedup"] = serde_json::to_value(dedup)?;
    active.topology_context = Set(Some(context));
    if creating {
        active.insert(txn).await?;
    } else {
        active.update(txn).await?;
    }
    if creating {
        incident_events::append_in_transaction(txn, org_id, &id, IncidentEvent::created()).await?;
    }
    Ok(())
}

fn text(record: &Map<String, Value>, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| {
            record.get(*key).and_then(|value| match value {
                Value::String(text) => Some(text.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
        })
        .unwrap_or_default()
        .chars()
        .take(16_384)
        .collect()
}
fn hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
fn normalize_stack(stack: &str) -> String {
    stack
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| {
            !line.starts_with("Traceback (")
                && !line.starts_with("Caused by:")
                && !(line.contains(": ") && !line.starts_with("at ") && !line.starts_with("File "))
        })
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    #[test]
    fn error_and_exception_extraction() {
        let good = json!({"trace_id":"a","span_id":"b","span_status":"OK"});
        assert!(extract_trace_errors("traces", 1, good.as_object().unwrap()).is_empty());
        let error =
            json!({"trace_id":"a","span_id":"b","span_status":"ERROR","operation_name":"GET /x"});
        assert!(!extract_trace_errors("traces", 1, error.as_object().unwrap()).is_empty());
        let exception = json!({"trace_id":"a","span_id":"b","events": "[{\"name\":\"exception\",\"attributes\":{\"exception.type\":\"TypeError\"}}]"});
        assert_eq!(
            extract_trace_errors("traces", 1, exception.as_object().unwrap())
                .pop()
                .unwrap()
                .metadata
                .exception_type,
            "TypeError"
        );
    }
    #[test]
    fn distinct_exceptions_in_one_span_are_extracted() {
        let record = json!({"trace_id":"a","span_id":"b","span_status":"ERROR","events":[{"name":"exception","exception.type":"ValueError"},{"name":"exception","exception.type":"TypeError"}]});
        let parsed = extract_trace_errors("traces", 1, record.as_object().unwrap());
        assert_eq!(parsed.len(), 2);
        assert_ne!(parsed[0].fingerprint, parsed[1].fingerprint);
    }
    #[test]
    fn serialized_otel_exception_preserves_details() {
        let event = common::meta::traces::Event {
            name: "exception".into(),
            _timestamp: 1,
            attributes: std::collections::HashMap::from([
                ("exception.type".into(), json!("ValueError")),
                ("exception.stacktrace".into(), json!("at app.js:1")),
            ]),
        };
        let record = json!({"trace_id":"a","span_id":"b","events": serde_json::to_string(&vec![event]).unwrap()});
        let parsed = extract_trace_errors("traces", 1, record.as_object().unwrap())
            .pop()
            .unwrap();
        assert_eq!(parsed.metadata.exception_type, "ValueError");
        assert_eq!(parsed.metadata.stacktrace, "at app.js:1");
    }
    #[test]
    fn python_stack_messages_do_not_change_group() {
        assert_eq!(
            normalize_stack(
                "Traceback (most recent call last):\n File \"app.py\", line 1\nValueError: dynamic 1"
            ),
            normalize_stack(
                "Traceback (most recent call last):\n File \"app.py\", line 1\nValueError: dynamic 2"
            )
        );
    }
    #[test]
    fn stack_message_does_not_change_group() {
        assert_eq!(
            normalize_stack("TypeError: dynamic 1\n at app (app.js:1:2)"),
            normalize_stack("TypeError: dynamic 2\n at app (app.js:1:2)")
        );
    }
}
