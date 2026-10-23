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

//! HTTP handlers for alert incident management

use axum::{
    Json,
    extract::{Path, Query},
    response::Response,
};
use openobserve_api_common::extractors::Headers;
use openobserve_core::auth::UserEmail;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::common::meta::http::HttpResponse as MetaHttpResponse;

/// Query parameters for listing incidents
#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct ListIncidentsQuery {
    /// Filter by status (open, acknowledged, resolved)
    #[serde(default)]
    pub status: Option<String>,
    /// Maximum number of results
    #[serde(default = "default_limit")]
    pub limit: u64,
    /// Offset for pagination
    #[serde(default)]
    pub offset: u64,
}

fn default_limit() -> u64 {
    50
}

/// Severity values for incident updates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum IncidentSeverity {
    P1,
    P2,
    P3,
    P4,
}

impl IncidentSeverity {
    pub fn as_str(&self) -> &str {
        match self {
            IncidentSeverity::P1 => "P1",
            IncidentSeverity::P2 => "P2",
            IncidentSeverity::P3 => "P3",
            IncidentSeverity::P4 => "P4",
        }
    }
}

/// Status values for incident updates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum IncidentStatus {
    Open,
    Acknowledged,
    Resolved,
}

impl IncidentStatus {
    pub fn as_str(&self) -> &str {
        match self {
            IncidentStatus::Open => "open",
            IncidentStatus::Acknowledged => "acknowledged",
            IncidentStatus::Resolved => "resolved",
        }
    }
}

/// Update payload enum for incident field updates
/// Ensures only one field can be updated per request
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
#[cfg_attr(not(feature = "enterprise"), serde(deny_unknown_fields))]
pub enum UpdatePayload {
    /// Update incident title
    Title { title: String },
    /// Update incident severity
    Severity { severity: IncidentSeverity },
    /// Update incident status
    Status { status: IncidentStatus },
}

/// Response for list incidents
#[derive(Debug, Serialize, ToSchema)]
pub struct ListIncidentsResponse {
    pub incidents: Vec<config::meta::alerts::incidents::Incident>,
    pub total: u64,
}

#[cfg(feature = "enterprise")]
/// ListIncidents
#[utoipa::path(
    get,
    path = "/v2/{org_id}/alerts/incidents",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "ListIncidents",
    summary = "List alert incidents",
    description = "Retrieves a list of correlated alert incidents with optional status filtering and pagination.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ListIncidentsQuery,
    ),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = ListIncidentsResponse),
        (status = 500, description = "Internal error", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "list"})),
        ("x-o2-mcp" = json!({"description": "List all incidents", "category": "alerts"}))
    )
)]
pub async fn list_incidents(
    Path(org_id): Path<String>,
    Query(query): Query<ListIncidentsQuery>,
) -> Response {
    match openobserve_core::alerts::incidents::list_incidents(
        &org_id,
        query.status.as_deref(),
        query.limit,
        query.offset,
    )
    .await
    {
        Ok((incidents, total)) => {
            MetaHttpResponse::json(ListIncidentsResponse { incidents, total })
        }
        Err(e) => MetaHttpResponse::internal_error(e),
    }
}

#[cfg(feature = "enterprise")]
/// GetIncident
#[utoipa::path(
    get,
    path = "/v2/{org_id}/alerts/incidents/{incident_id}",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "GetIncident",
    summary = "Get incident details",
    description = "Retrieves detailed information about a specific incident including all correlated alerts.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ("incident_id" = String, Path, description = "Incident ID"),
    ),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = config::meta::alerts::incidents::IncidentWithAlerts),
        (status = 404, description = "Not found", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "get"})),
        ("x-o2-mcp" = json!({"description": "Get an incident's details", "category": "alerts", "pinned": true}))
    )
)]
pub async fn get_incident(Path((org_id, incident_id)): Path<(String, String)>) -> Response {
    match openobserve_core::alerts::incidents::get_incident_with_alerts(&org_id, &incident_id).await
    {
        Ok(Some(incident)) => MetaHttpResponse::json(incident),
        Ok(None) => MetaHttpResponse::not_found("Incident not found"),
        Err(e) => MetaHttpResponse::internal_error(e),
    }
}

#[cfg(feature = "enterprise")]
#[utoipa::path(
    patch,
    path = "/v2/{org_id}/alerts/incidents/{incident_id}/update",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "UpdateIncident",
    summary = "Update incident fields",
    description = "Updates incident title, severity, or status. This endpoint is only available with enterprise features enabled.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ("incident_id" = String, Path, description = "Incident ID"),
    ),
    request_body(content = UpdatePayload, description = "Field to update", content_type = "application/json"),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = config::meta::alerts::incidents::Incident),
        (status = 403, description = "Enterprise feature", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "update"})),
        ("x-o2-mcp" = json!({"description": "Update an incident's title or severity. Status changes (resolve, acknowledge, reopen) are NOT supported via this tool — they must be performed by a human in the UI.", "category": "alerts"}))
    )
)]
pub async fn update_incident(
    path: Path<(String, String)>,
    Headers(user_email): Headers<UserEmail>,
    Json(body): Json<UpdatePayload>,
) -> Response {
    let (org_id, incident_id) = path.0;
    let user_id = user_email.user_id;

    match body {
        UpdatePayload::Title { title } => {
            if title.trim().is_empty() {
                return MetaHttpResponse::bad_request("Title cannot be empty");
            }
            if title.len() > 255 {
                return MetaHttpResponse::bad_request("Title cannot exceed 255 characters");
            }

            match openobserve_core::alerts::incidents::update_title(
                &org_id,
                &incident_id,
                &title,
                &user_id,
            )
            .await
            {
                Ok(incident) => MetaHttpResponse::json(incident),
                Err(e) => {
                    if e.to_string().contains("not found") {
                        MetaHttpResponse::not_found("Incident not found")
                    } else {
                        MetaHttpResponse::internal_error(e)
                    }
                }
            }
        }
        UpdatePayload::Severity { severity } => {
            match openobserve_core::alerts::incidents::update_severity(
                &org_id,
                &incident_id,
                severity.as_str(),
                &user_id,
            )
            .await
            {
                Ok(incident) => {
                    use o2_enterprise::enterprise::common::config::get_config as get_o2_config;
                    let cooldown = get_o2_config().incidents.reanalysis_cooldown_minutes;
                    let events = infra::table::incident_events::get(&org_id, &incident_id)
                        .await
                        .unwrap_or_default();
                    let in_flight = openobserve_core::alerts::incidents::is_analysis_in_flight(
                        &events,
                        cooldown * 2,
                    );
                    MetaHttpResponse::json(UpdateSeverityResponse {
                        incident,
                        analysis_in_flight: in_flight,
                    })
                }
                Err(e) => {
                    if e.to_string().contains("not found") {
                        MetaHttpResponse::not_found("Incident not found")
                    } else {
                        MetaHttpResponse::internal_error(e)
                    }
                }
            }
        }
        UpdatePayload::Status { status } => {
            match openobserve_core::alerts::incidents::update_status(
                &org_id,
                &incident_id,
                status.as_str(),
                &user_id,
            )
            .await
            {
                Ok(incident) => MetaHttpResponse::json(incident),
                Err(e) => {
                    if e.to_string().contains("not found") {
                        MetaHttpResponse::not_found("Incident not found")
                    } else {
                        MetaHttpResponse::internal_error(e)
                    }
                }
            }
        }
    }
}

#[cfg(feature = "enterprise")]
/// GetExternalAlertPayload
#[utoipa::path(
    get,
    path = "/v2/{org_id}/alerts/incidents/external-alerts/{external_alert_id}/payload",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "GetExternalAlertPayload",
    summary = "Get the raw payload of an external alert",
    description = "Retrieves the original, unmodified webhook payload received for an external alert event. Used to inspect exactly what a source system (Grafana, Alertmanager, etc.) sent.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ("external_alert_id" = String, Path, description = "External alert ID"),
    ),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = ()),
        (status = 404, description = "Not found", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "get"})),
        ("x-o2-mcp" = json!({"description": "Get the raw payload of an external alert", "category": "alerts"}))
    )
)]
pub async fn get_external_alert_payload(
    Path((org_id, external_alert_id)): Path<(String, String)>,
) -> Response {
    match infra::table::external_alerts::get_by_id(&org_id, &external_alert_id).await {
        Ok(Some(record)) => MetaHttpResponse::json(serde_json::json!({
            "id": record.id,
            "detected_source": record.detected_source,
            "source_url": record.source_url,
            "first_seen_at": record.first_seen_at,
            "last_seen_at": record.last_seen_at,
            "last_payload": record.last_payload,
        })),
        Ok(None) => MetaHttpResponse::not_found("External alert not found"),
        Err(e) => MetaHttpResponse::internal_error(e),
    }
}

#[cfg(feature = "enterprise")]
/// GetIncidentStats
#[utoipa::path(
    get,
    path = "/v2/{org_id}/alerts/incidents/stats",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "GetIncidentStats",
    summary = "Get incident statistics",
    description = "Retrieves statistics about incidents including counts by status and severity.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
    ),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = config::meta::alerts::incidents::IncidentStats),
        (status = 500, description = "Internal error", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "get"})),
        ("x-o2-mcp" = json!({"description": "Get incident statistics", "category": "alerts"}))
    )
)]
pub async fn get_incident_stats(Path(org_id): Path<String>) -> Response {
    // Get counts - simple implementation
    let open_count = match infra::table::alert_incidents::count_open(&org_id).await {
        Ok(c) => c as i64,
        Err(e) => return MetaHttpResponse::internal_error(e),
    };

    let stats = config::meta::alerts::incidents::IncidentStats {
        total_incidents: 0, // Would need additional query
        open_incidents: open_count,
        acknowledged_incidents: 0,
        resolved_incidents: 0,
        by_severity: std::collections::HashMap::new(),
        by_service: std::collections::HashMap::new(),
        mttr_minutes: None,
        alerts_per_incident_avg: 0.0,
    };

    MetaHttpResponse::json(stats)
}

/// Response for severity update — wraps Incident and signals whether analysis is running
#[derive(Debug, Serialize, ToSchema)]
pub struct UpdateSeverityResponse {
    #[serde(flatten)]
    pub incident: config::meta::alerts::incidents::Incident,
    pub analysis_in_flight: bool,
}

/// Response for RCA analysis
#[derive(Debug, Serialize, ToSchema)]
pub struct RcaResponse {
    pub rca_content: String,
}

/// Response for cancelling an in-flight RCA analysis
#[derive(Debug, Serialize, ToSchema)]
pub struct CancelRcaResponse {
    pub message: String,
    /// Whether an in-process task handle was found and aborted on this node. False when the
    /// analysis is running on another node — the cancellation event is still recorded.
    pub aborted_local_task: bool,
}

/// Response listing an incident's current and superseded RCA reports
#[derive(Debug, Serialize, ToSchema)]
pub struct RcaHistoryResponse {
    /// The active report, if one has been generated
    pub current: Option<String>,
    /// Superseded reports, newest first
    pub previous: Vec<config::meta::alerts::incidents::ArchivedRcaReport>,
}

/// Query parameters for RCA trigger
#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct TriggerRcaQuery {
    /// Use streaming response (default: false)
    #[serde(default)]
    pub stream: bool,
    /// Treat this as a user-initiated reanalysis — bypasses cooldown (default: false)
    #[serde(default)]
    pub reanalysis: bool,
    /// Feed the previous report to the agent so it builds on it instead of starting
    /// from scratch (default: false — each run is a fresh, independent analysis).
    #[serde(default)]
    pub build_on_previous: bool,
}

#[cfg(feature = "enterprise")]
/// TriggerIncidentRca
#[utoipa::path(
    post,
    path = "/v2/{org_id}/alerts/incidents/{incident_id}/rca",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "TriggerIncidentRca",
    summary = "Trigger RCA analysis for an incident",
    description = "Triggers root cause analysis for an incident. Use stream=true query parameter for streaming response, otherwise returns complete result as JSON.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ("incident_id" = String, Path, description = "Incident ID"),
        TriggerRcaQuery,
    ),
    responses(
        (status = 200, description = "RCA analysis completed or SSE stream", content_type = "application/json", body = RcaResponse),
        (status = 402, description = "AI credits exhausted", content_type = "application/json", body = ()),
        (status = 412, description = "Paid usage requires organization consent", content_type = "application/json", body = ()),
        (status = 404, description = "Not found", content_type = "application/json", body = ()),
        (status = 503, description = "RCA agent or billing state unavailable", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "update"})),
        ("x-o2-mcp" = json!({"description": "Manually trigger incident RCA", "category": "alerts"}))
    )
)]
pub async fn trigger_incident_rca(
    Path((org_id, incident_id)): Path<(String, String)>,
    Headers(user_email): Headers<UserEmail>,
    Query(query): Query<TriggerRcaQuery>,
) -> Response {
    use o2_enterprise::enterprise::{
        alerts::rca_service, common::config::get_config as get_o2_config,
    };

    let o2_cfg = get_o2_config();

    // Check if RCA is enabled
    if !o2_cfg.incidents.enabled || !o2_cfg.incidents.rca_enabled {
        return MetaHttpResponse::bad_request("RCA is not enabled");
    }

    if !o2_cfg.ai.has_agent_target() {
        return axum::response::Response::builder()
            .status(axum::http::StatusCode::SERVICE_UNAVAILABLE)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"error": "RCA agent URL is not configured"}).to_string(),
            ))
            .unwrap();
    }

    // In-flight guard. Keep the events to distinguish a first analysis from
    // a rerun when a caller omits the explicit reanalysis flag.
    let cooldown = o2_cfg.incidents.reanalysis_cooldown_minutes;
    let events = infra::table::incident_events::get(&org_id, &incident_id)
        .await
        .unwrap_or_default();
    if openobserve_core::alerts::incidents::is_analysis_in_flight(&events, cooldown * 2) {
        return MetaHttpResponse::bad_request("Analysis already in progress");
    }

    // Validate the incident before consuming quota or starting the lifecycle. Existence check
    // only: the builder below re-derives the context, so read the one row rather than hydrating
    // every alert on the incident.
    match infra::table::alert_incidents::get(&org_id, &incident_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return MetaHttpResponse::not_found("Incident not found"),
        Err(e) => return MetaHttpResponse::internal_error(e),
    }

    // A reanalysis runs through the shared trigger, which skips it when the team's L0 is off;
    // refuse it before authorization so the skipped run is never charged.
    if query.reanalysis
        && !openobserve_core::alerts::incidents::rca_will_run(&org_id, &incident_id).await
    {
        return MetaHttpResponse::bad_request("AI SRE is turned off for this incident's priority");
    }

    #[cfg(feature = "cloud")]
    let usage_permit = {
        let is_reanalysis = query.reanalysis
            || events.iter().any(|event| {
                matches!(
                    event.event_type,
                    config::meta::alerts::incidents::IncidentEventType::AIAnalysisComplete
                )
            });
        let feature = if is_reanalysis {
            openobserve_core::trial_quota::TrialQuotaFeature::IncidentReAnalysis
        } else {
            openobserve_core::trial_quota::TrialQuotaFeature::NewIncident
        };
        let usage_context = openobserve_core::trial_quota::AiUsageContext {
            user_email: user_email.user_id.clone(),
            incident_id: Some(incident_id.clone()),
            ..Default::default()
        };
        match openobserve_core::trial_quota::authorize_ai_usage(&org_id, feature, &usage_context)
            .await
        {
            Ok(permit) => Some(permit),
            Err(error) => {
                return crate::request::ai::chat::ai_authorization_error_response(error);
            }
        }
    };
    #[cfg(not(feature = "cloud"))]
    let usage_permit = None;

    // Authorization succeeded. Every error below must terminate the lifecycle.
    let _ = openobserve_core::incidents::append_event(
        &org_id,
        &incident_id,
        config::meta::alerts::incidents::IncidentEvent::ai_analysis_begin(),
    )
    .await;

    // Build RCA context. Each run is a fresh analysis unless the caller explicitly opts
    // into continuity — chaining every run compounds the report (and the agent's context)
    // and carries any early mistake forward with no way to shake it off.
    let previous_analysis = if query.build_on_previous {
        infra::table::alert_incidents::get_topology(&org_id, &incident_id)
            .await
            .ok()
            .flatten()
            .and_then(|t| t.suggested_root_cause)
            .filter(|s| !s.is_empty())
    } else {
        None
    };
    // The single builder both this endpoint and the autonomous path call, so the two can no
    // longer disagree about severity or past_causes (C1).
    let context =
        rca_service::build_incident_context(&org_id, &incident_id, previous_analysis).await;

    // Create RCA agent client with SA credentials
    let (email, token) =
        match openobserve_core::organization::get_sre_agent_credentials(&org_id).await {
            Ok(creds) => creds,
            Err(e) => {
                let _ = openobserve_core::incidents::append_event(
                    &org_id,
                    &incident_id,
                    config::meta::alerts::incidents::IncidentEvent::ai_analysis_failed(
                        "Credentials failed",
                        config::meta::alerts::incidents::AnalysisTriggerType::Manual,
                        Some(format!("{:#}", e)),
                    ),
                )
                .await;
                return MetaHttpResponse::internal_error(format!(
                    "Failed to get SRE agent credentials: {e}"
                ));
            }
        };
    let auth_header = openobserve_core::auth::build_basic_auth_header(&email, &token);
    let client = match o2_enterprise::enterprise::ai::client::get_agent_client() {
        Some(c) => c,
        None => {
            // Emit failure event instead of misleading Complete event
            let _ = openobserve_core::incidents::append_event(
                &org_id,
                &incident_id,
                config::meta::alerts::incidents::IncidentEvent::ai_analysis_failed(
                    "Agent not configured",
                    config::meta::alerts::incidents::AnalysisTriggerType::Manual,
                    None,
                ),
            )
            .await;
            return MetaHttpResponse::internal_error("RCA agent client not initialized");
        }
    };

    // Check agent health
    if let Err(e) = client.health(&auth_header).await {
        // Emit failure event instead of misleading Complete event
        let _ = openobserve_core::incidents::append_event(
            &org_id,
            &incident_id,
            config::meta::alerts::incidents::IncidentEvent::ai_analysis_failed(
                "Agent unavailable",
                config::meta::alerts::incidents::AnalysisTriggerType::Manual,
                Some(format!("{:#}", e)),
            ),
        )
        .await;

        return axum::response::Response::builder()
            .status(axum::http::StatusCode::SERVICE_UNAVAILABLE)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"error": format!("RCA agent not available: {e}")}).to_string(),
            ))
            .unwrap();
    }

    // User-initiated reanalysis: fire-and-forget — spawn agent in background, return 202
    // immediately. Begin was already emitted above; the spawn passes begin_already_emitted=true
    // to skip duplicate emission and the in-flight/cooldown guards.
    if query.reanalysis {
        let org_id_bg = org_id.clone();
        let incident_id_bg = incident_id.clone();
        let user_email_bg = user_email.user_id.clone();
        let build_on_previous = query.build_on_previous;
        let handle = tokio::spawn(async move {
            if let Err(e) = openobserve_core::alerts::incidents::trigger_rca_for_incident(
                org_id_bg.clone(),
                incident_id_bg.clone(),
                true,
                true,
                user_email_bg,
                build_on_previous,
                usage_permit,
            )
            .await
            {
                log::warn!(
                    "[INCIDENTS::RCA] Background reanalysis failed for {incident_id_bg}: {e}"
                );

                // Emit failure event for manual reanalysis background task
                if let Err(emit_err) = openobserve_core::incidents::append_event(
                    &org_id_bg,
                    &incident_id_bg,
                    config::meta::alerts::incidents::IncidentEvent::ai_analysis_failed(
                        "Manual reanalysis background task failed",
                        config::meta::alerts::incidents::AnalysisTriggerType::Manual,
                        Some(format!("{:#}", e)),
                    ),
                )
                .await
                {
                    log::error!(
                        "[INCIDENTS::RCA] Failed to emit AIAnalysisFailed event for {incident_id_bg}: {emit_err}"
                    );
                }
            }
            openobserve_core::alerts::incidents::unregister_rca_task(&org_id_bg, &incident_id_bg);
        });
        openobserve_core::alerts::incidents::register_rca_task(
            &org_id,
            &incident_id,
            handle.abort_handle(),
        );

        return axum::response::Response::builder()
            .status(axum::http::StatusCode::ACCEPTED)
            .header(axum::http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({"message": "Analysis started"}).to_string(),
            ))
            .unwrap();
    }

    // Choose streaming or non-streaming based on query parameter
    if query.stream {
        // AIAnalysisComplete is emitted inside the stream closure (rca_service.rs)
        // after the stream is fully drained, not here.
        let stream = match rca_service::analyze_incident_stream(
            (*client).clone(),
            context,
            auth_header.clone(),
            openobserve_core::incidents::append_event_send,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                let _ = openobserve_core::incidents::append_event(
                    &org_id,
                    &incident_id,
                    config::meta::alerts::incidents::IncidentEvent::ai_analysis_failed(
                        "Stream start failed",
                        config::meta::alerts::incidents::AnalysisTriggerType::Manual,
                        Some(format!("{:#}", e)),
                    ),
                )
                .await;
                return MetaHttpResponse::internal_error(format!(
                    "Failed to start RCA stream: {e}"
                ));
            }
        };

        axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
            .body(axum::body::Body::from_stream(stream))
            .unwrap()
    } else {
        // Perform RCA analysis (non-streaming)
        let rca_content =
            match rca_service::analyze_incident((*client).clone(), context, &auth_header).await {
                Ok(content) => content,
                Err(e) => {
                    let _ = openobserve_core::incidents::append_event(
                        &org_id,
                        &incident_id,
                        config::meta::alerts::incidents::IncidentEvent::ai_analysis_failed(
                            "Service call failed",
                            config::meta::alerts::incidents::AnalysisTriggerType::Manual,
                            Some(format!("{:#}", e)),
                        ),
                    )
                    .await;
                    return MetaHttpResponse::internal_error(format!("Failed to perform RCA: {e}"));
                }
            };

        // Emit AIAnalysisComplete on success
        let _ = openobserve_core::incidents::append_event(
            &org_id,
            &incident_id,
            config::meta::alerts::incidents::IncidentEvent::ai_analysis_complete(),
        )
        .await;

        MetaHttpResponse::json(RcaResponse { rca_content })
    }
}

#[cfg(feature = "enterprise")]
/// CancelIncidentRca
#[utoipa::path(
    delete,
    path = "/v2/{org_id}/alerts/incidents/{incident_id}/rca",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "CancelIncidentRca",
    summary = "Cancel the in-flight RCA analysis for an incident",
    description = "Aborts a running root cause analysis and records a terminal cancellation event, releasing the in-flight guard so a new analysis can be started immediately.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ("incident_id" = String, Path, description = "Incident ID"),
    ),
    responses(
        (status = 200, description = "Analysis cancelled", content_type = "application/json", body = CancelRcaResponse),
        (status = 400, description = "No analysis in progress", content_type = "application/json", body = ()),
        (status = 500, description = "Internal error", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "update"})),
        ("x-o2-mcp" = json!({"description": "Cancel a running incident RCA", "category": "alerts"}))
    )
)]
pub async fn cancel_incident_rca(
    Path((org_id, incident_id)): Path<(String, String)>,
    Headers(user_email): Headers<UserEmail>,
) -> Response {
    use o2_enterprise::enterprise::common::config::get_config as get_o2_config;

    let cooldown = get_o2_config().incidents.reanalysis_cooldown_minutes;

    // The in-flight check lives inside cancel_rca_for_incident, after the abort handle is
    // atomically removed — checking here first would leave a window in which a new
    // analysis could start and be cancelled in place of the one the user targeted.
    match openobserve_core::alerts::incidents::cancel_rca_for_incident(
        &org_id,
        &incident_id,
        Some(user_email.user_id.clone()),
        cooldown * 2,
    )
    .await
    {
        // Nothing running — report it rather than writing a spurious terminal event.
        Ok(None) => MetaHttpResponse::bad_request("No analysis is currently in progress"),
        Ok(Some(aborted)) => MetaHttpResponse::json(CancelRcaResponse {
            message: "Analysis cancelled".to_string(),
            aborted_local_task: aborted,
        }),
        Err(e) => MetaHttpResponse::internal_error(format!("Failed to cancel analysis: {e}")),
    }
}

#[cfg(feature = "enterprise")]
/// GetIncidentRcaHistory
#[utoipa::path(
    get,
    path = "/v2/{org_id}/alerts/incidents/{incident_id}/rca/history",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "GetIncidentRcaHistory",
    summary = "List RCA reports for an incident",
    description = "Returns the current root cause analysis report plus any superseded reports retained for this incident, newest first.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ("incident_id" = String, Path, description = "Incident ID"),
    ),
    responses(
        (status = 200, description = "RCA report history", content_type = "application/json", body = RcaHistoryResponse),
        (status = 500, description = "Internal error", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "get"})),
        ("x-o2-mcp" = json!({"description": "List past incident RCA reports", "category": "alerts"}))
    )
)]
pub async fn get_incident_rca_history(
    Path((org_id, incident_id)): Path<(String, String)>,
) -> Response {
    let topology = match infra::table::alert_incidents::get_topology(&org_id, &incident_id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return MetaHttpResponse::json(RcaHistoryResponse {
                current: None,
                previous: vec![],
            });
        }
        Err(e) => return MetaHttpResponse::internal_error(e),
    };

    MetaHttpResponse::json(RcaHistoryResponse {
        current: topology.suggested_root_cause,
        previous: topology.previous_analyses,
    })
}

/// Get incident events timeline
#[cfg(feature = "enterprise")]
pub async fn get_incident_events(Path((org_id, incident_id)): Path<(String, String)>) -> Response {
    let events = match infra::table::incident_events::get(&org_id, &incident_id).await {
        Ok(events) => events,
        Err(e) => return MetaHttpResponse::internal_error(format!("Failed to get events: {e}")),
    };

    // Self-heal timelines emptied by the pre-fix read/write cycle (releases up to v0.91.x).
    // Repairing lazily on read avoids a migration that would rewrite every incident row;
    // an empty timeline is cheap to inspect and, for healthy incidents, is a normal state
    // that reconstruct_if_empty leaves alone once there is nothing to rebuild.
    if events.is_empty() {
        match infra::table::incident_events::reconstruct_if_empty(&org_id, &incident_id).await {
            Ok(Some(_)) => match infra::table::incident_events::get(&org_id, &incident_id).await {
                Ok(rebuilt) => {
                    return MetaHttpResponse::json(serde_json::json!({
                        "events": rebuilt,
                        // Flags that the timeline was rebuilt from incident/alert rows and is
                        // missing anything that lived only in the lost blob (comments,
                        // acknowledgements, RCA activity).
                        "partial_reconstruction": true,
                    }));
                }
                Err(e) => {
                    return MetaHttpResponse::internal_error(format!("Failed to get events: {e}"));
                }
            },
            Ok(None) => {}
            // Repair is best-effort: a failure here must not fail the read.
            Err(e) => {
                log::warn!("[INCIDENTS] timeline reconstruction failed for {incident_id}: {e}");
            }
        }
    }

    MetaHttpResponse::json(serde_json::json!({ "events": events }))
}

/// Get incident events timeline (OSS)
#[cfg(not(feature = "enterprise"))]
pub async fn get_incident_events(Path((org_id, incident_id)): Path<(String, String)>) -> Response {
    if !config::get_config().oss_incidents.enabled {
        return MetaHttpResponse::forbidden("Incidents are disabled");
    }
    match openobserve_core::alerts::incidents::get_events(&org_id, &incident_id).await {
        Ok(events) => MetaHttpResponse::json(serde_json::json!({ "events": events })),
        Err(error) => oss_incident_error(error),
    }
}

/// Post a comment on an incident
#[cfg(feature = "enterprise")]
pub async fn post_incident_comment(
    Path((org_id, incident_id)): Path<(String, String)>,
    Headers(user_email): Headers<UserEmail>,
    Json(body): Json<CommentRequest>,
) -> Response {
    use config::meta::alerts::incidents::IncidentEvent;

    if body.comment.trim().is_empty() {
        return MetaHttpResponse::bad_request("Comment cannot be blank");
    }
    if body.comment.len() > 10_000 {
        return MetaHttpResponse::bad_request("Comment must be 10,000 characters or fewer");
    }

    let event = IncidentEvent::comment(user_email.user_id, body.comment);

    match openobserve_core::incidents::append_event(&org_id, &incident_id, event).await {
        Ok(()) => MetaHttpResponse::ok("Comment added"),
        Err(e) => MetaHttpResponse::internal_error(format!("Failed to add comment: {e}")),
    }
}

/// Post a comment (OSS)
#[cfg(not(feature = "enterprise"))]
pub async fn post_incident_comment(
    Path((org_id, incident_id)): Path<(String, String)>,
    Headers(actor): Headers<UserEmail>,
    body: Result<Json<CommentRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !config::get_config().oss_incidents.enabled {
        return MetaHttpResponse::forbidden("Incidents are disabled");
    }
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => return MetaHttpResponse::bad_request(error.body_text()),
    };
    if body.comment.trim().is_empty() || body.comment.trim().chars().count() > 10_000 {
        return MetaHttpResponse::bad_request(
            "Comment must contain between 1 and 10000 characters",
        );
    }
    match openobserve_core::alerts::incidents::add_comment(
        &org_id,
        &incident_id,
        &actor.user_id,
        &body.comment,
    )
    .await
    {
        Ok(()) => MetaHttpResponse::ok("Comment added"),
        Err(error) => oss_incident_error(error),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CommentRequest {
    pub comment: String,
}

#[cfg(not(feature = "enterprise"))]
#[utoipa::path(
    post,
    path = "/v2/{org_id}/alerts/incidents/{incident_id}/rca",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "TriggerIncidentRca",
    summary = "Trigger RCA analysis for an incident",
    description = "Triggers root cause analysis for an incident. This endpoint is only available with enterprise features enabled.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ("incident_id" = String, Path, description = "Incident ID"),
    ),
    responses(
        (status = 200, description = "SSE stream", content_type = "text/event-stream"),
        (status = 403, description = "Enterprise feature", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "update"})),
        ("x-o2-mcp" = json!({"description": "Manually trigger incident RCA", "category": "alerts"}))
    )
)]
pub async fn trigger_incident_rca(_path: Path<(String, String)>) -> Response {
    MetaHttpResponse::forbidden("Not Supported")
}

#[cfg(not(feature = "enterprise"))]
#[utoipa::path(
    get,
    path = "/v2/{org_id}/alerts/incidents",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "ListIncidents",
    summary = "List alert incidents",
    description = "Retrieves a list of correlated alert incidents. Available when incident management is enabled.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ListIncidentsQuery,
    ),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = ListIncidentsResponse),
        (status = 403, description = "Enterprise feature", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "list"})),
        ("x-o2-mcp" = json!({"description": "List all incidents", "category": "alerts"}))
    )
)]
pub async fn list_incidents(
    Path(org_id): Path<String>,
    query: Result<Query<ListIncidentsQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    if !config::get_config().oss_incidents.enabled {
        return MetaHttpResponse::forbidden("Incidents are disabled");
    }
    let Query(query) = match query {
        Ok(query) => query,
        Err(error) => return MetaHttpResponse::bad_request(error.body_text()),
    };
    if !(1..=500).contains(&query.limit) || query.offset > i64::MAX as u64 {
        return MetaHttpResponse::bad_request(
            "Limit must be between 1 and 500 and offset must fit a signed integer",
        );
    }
    if let Some(status) = &query.status
        && status
            .parse::<config::meta::alerts::incidents::IncidentStatus>()
            .is_err()
    {
        return MetaHttpResponse::bad_request("Invalid incident status");
    }
    match openobserve_core::alerts::incidents::list_incidents(
        &org_id,
        query.status.as_deref(),
        query.limit,
        query.offset,
    )
    .await
    {
        Ok((incidents, total)) => {
            MetaHttpResponse::json(ListIncidentsResponse { incidents, total })
        }
        Err(error) => oss_incident_error(error),
    }
}

#[cfg(not(feature = "enterprise"))]
#[utoipa::path(
    get,
    path = "/v2/{org_id}/alerts/incidents/{incident_id}",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "GetIncident",
    summary = "Get incident details",
    description = "Retrieves detailed information about a specific incident. Available when incident management is enabled.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ("incident_id" = String, Path, description = "Incident ID"),
    ),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = config::meta::alerts::incidents::IncidentWithAlerts),
        (status = 403, description = "Enterprise feature", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "get"})),
        ("x-o2-mcp" = json!({"description": "Get an incident's details", "category": "alerts"}))
    )
)]
pub async fn get_incident(Path((org_id, incident_id)): Path<(String, String)>) -> Response {
    if !config::get_config().oss_incidents.enabled {
        return MetaHttpResponse::forbidden("Incidents are disabled");
    }
    match openobserve_core::alerts::incidents::get_incident_with_alerts(&org_id, &incident_id).await
    {
        Ok(Some(incident)) => MetaHttpResponse::json(incident),
        Ok(None) => MetaHttpResponse::not_found("Incident not found"),
        Err(error) => oss_incident_error(error),
    }
}

#[cfg(not(feature = "enterprise"))]
#[utoipa::path(
    get,
    path = "/v2/{org_id}/alerts/incidents/external-alerts/{external_alert_id}/payload",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "GetExternalAlertPayload",
    summary = "Get the raw payload of an external alert",
    description = "Retrieves the original webhook payload for an external alert event. This endpoint is only available with enterprise features enabled.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ("external_alert_id" = String, Path, description = "External alert ID"),
    ),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = ()),
        (status = 403, description = "Enterprise feature", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "get"})),
        ("x-o2-mcp" = json!({"description": "Get the raw payload of an external alert", "category": "alerts"}))
    )
)]
pub async fn get_external_alert_payload(_path: Path<(String, String)>) -> Response {
    MetaHttpResponse::forbidden("Not Supported")
}

#[cfg(not(feature = "enterprise"))]
#[utoipa::path(
    get,
    path = "/v2/{org_id}/alerts/incidents/stats",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "GetIncidentStats",
    summary = "Get incident statistics",
    description = "Retrieves statistics about incidents. Available when incident management is enabled.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
    ),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = config::meta::alerts::incidents::IncidentStats),
        (status = 403, description = "Enterprise feature", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "get"})),
        ("x-o2-mcp" = json!({"description": "Get incident statistics", "category": "alerts"}))
    )
)]
pub async fn get_incident_stats(Path(org_id): Path<String>) -> Response {
    if !config::get_config().oss_incidents.enabled {
        return MetaHttpResponse::forbidden("Incidents are disabled");
    }
    match openobserve_core::alerts::incidents::get_incident_stats(&org_id).await {
        Ok(stats) => MetaHttpResponse::json(stats),
        Err(error) => oss_incident_error(error),
    }
}

#[cfg(not(feature = "enterprise"))]
#[utoipa::path(
    patch,
    path = "/v2/{org_id}/alerts/incidents/{incident_id}/update",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "UpdateIncident",
    summary = "Update incident fields",
    description = "Updates incident title, severity, or status. Available when incident management is enabled.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ("incident_id" = String, Path, description = "Incident ID"),
    ),
    request_body(content = UpdatePayload, description = "Field to update", content_type = "application/json"),
    responses(
        (status = 200, description = "Success", content_type = "application/json", body = config::meta::alerts::incidents::Incident),
        (status = 403, description = "Enterprise feature", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "update"})),
        ("x-o2-mcp" = json!({"description": "Update an incident's title, severity, or status", "category": "alerts"}))
    )
)]
pub async fn update_incident(
    Path((org_id, incident_id)): Path<(String, String)>,
    Headers(actor): Headers<UserEmail>,
    body: Result<Json<UpdatePayload>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !config::get_config().oss_incidents.enabled {
        return MetaHttpResponse::forbidden("Incidents are disabled");
    }
    let Json(body) = match body {
        Ok(body) => body,
        Err(error) => return MetaHttpResponse::bad_request(error.body_text()),
    };
    let result = match body {
        UpdatePayload::Title { title } => {
            if title.trim().is_empty() || title.trim().chars().count() > 500 {
                return MetaHttpResponse::bad_request(
                    "Title must contain between 1 and 500 characters",
                );
            }
            openobserve_core::alerts::incidents::update_title(
                &org_id,
                &incident_id,
                &title,
                &actor.user_id,
            )
            .await
        }
        UpdatePayload::Status { status } => {
            openobserve_core::alerts::incidents::update_status(
                &org_id,
                &incident_id,
                status.as_str(),
                &actor.user_id,
            )
            .await
        }
        UpdatePayload::Severity { severity } => {
            return match openobserve_core::alerts::incidents::update_severity(
                &org_id,
                &incident_id,
                severity.as_str(),
                &actor.user_id,
            )
            .await
            {
                Ok(incident) => MetaHttpResponse::json(UpdateSeverityResponse {
                    incident,
                    analysis_in_flight: false,
                }),
                Err(error) => oss_incident_error(error),
            };
        }
    };
    match result {
        Ok(incident) => MetaHttpResponse::json(incident),
        Err(error) => oss_incident_error(error),
    }
}

#[cfg(not(feature = "enterprise"))]
#[utoipa::path(
    delete,
    path = "/v2/{org_id}/alerts/incidents/{incident_id}/rca",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "CancelIncidentRca",
    summary = "Cancel the in-flight RCA analysis for an incident",
    description = "Aborts a running root cause analysis. This endpoint is only available with enterprise features enabled.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ("incident_id" = String, Path, description = "Incident ID"),
    ),
    responses(
        (status = 403, description = "Enterprise feature", content_type = "application/json", body = ()),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "update"})),
        ("x-o2-mcp" = json!({"description": "Cancel a running incident RCA", "category": "alerts"}))
    )
)]
pub async fn cancel_incident_rca(
    _path: Path<(String, String)>,
    _user_email: Headers<UserEmail>,
) -> Response {
    MetaHttpResponse::forbidden("Not Supported")
}

#[cfg(not(feature = "enterprise"))]
#[utoipa::path(
    get,
    path = "/v2/{org_id}/alerts/incidents/{incident_id}/rca/history",
    context_path = "/api",
    tag = "Incidents",
    operation_id = "GetIncidentRcaHistory",
    summary = "List RCA reports for an incident",
    description = "Returns the current root cause analysis report plus any superseded reports. This endpoint is only available with enterprise features enabled.",
    security(("Authorization" = [])),
    params(
        ("org_id" = String, Path, description = "Organization name"),
        ("incident_id" = String, Path, description = "Incident ID"),
    ),
    responses(
        (status = 200, description = "RCA report history (always empty without enterprise features)", content_type = "application/json", body = RcaHistoryResponse),
    ),
    extensions(
        ("x-o2-ratelimit" = json!({"module": "Alerts", "operation": "get"})),
        ("x-o2-mcp" = json!({"description": "List past incident RCA reports", "category": "alerts"}))
    )
)]
pub async fn get_incident_rca_history(_path: Path<(String, String)>) -> Response {
    MetaHttpResponse::json(RcaHistoryResponse {
        current: None,
        previous: vec![],
    })
}

#[cfg(not(feature = "enterprise"))]
fn oss_incident_error(error: anyhow::Error) -> Response {
    match error.to_string().as_str() {
        "Incident not found" => MetaHttpResponse::not_found("Incident not found"),
        "Only open incidents can be acknowledged" => MetaHttpResponse::bad_request(error),
        _ => MetaHttpResponse::internal_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "enterprise"))]
    #[tokio::test]
    async fn oss_incidents_reject_invalid_input_before_storage() {
        let response = list_incidents(
            Path("default".into()),
            Ok(Query(ListIncidentsQuery {
                status: None,
                limit: 0,
                offset: 0,
            })),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let response = update_incident(
            Path(("default".into(), "missing".into())),
            Headers(UserEmail {
                user_id: "actor@example.com".into(),
            }),
            Ok(Json(UpdatePayload::Title { title: "  ".into() })),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let response = post_incident_comment(
            Path(("default".into(), "missing".into())),
            Headers(UserEmail {
                user_id: "actor@example.com".into(),
            }),
            Ok(Json(CommentRequest {
                comment: " ".into(),
            })),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[cfg(not(feature = "enterprise"))]
    #[tokio::test]
    async fn oss_incidents_reject_malformed_and_ambiguous_update_bodies() {
        use axum::extract::FromRequest;
        for body in [
            r#"{"severity":"P5"}"#,
            r#"{"status":"unknown"}"#,
            r#"{"title":"title","status":"resolved"}"#,
            "{",
        ] {
            let request = axum::http::Request::builder()
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap();
            let body = Json::<UpdatePayload>::from_request(request, &()).await;
            let response = update_incident(
                Path(("default".into(), "missing".into())),
                Headers(UserEmail {
                    user_id: "actor@example.com".into(),
                }),
                body,
            )
            .await;
            assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        }
        for (status, limit, offset) in [
            (None, 501, 0),
            (None, 1, u64::MAX),
            (Some("unknown".into()), 1, 0),
        ] {
            let response = list_incidents(
                Path("default".into()),
                Ok(Query(ListIncidentsQuery {
                    status,
                    limit,
                    offset,
                })),
            )
            .await;
            assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        }
    }

    #[cfg(not(feature = "enterprise"))]
    #[tokio::test]
    async fn oss_incidents_handlers_keep_organization_and_actor() {
        use sea_orm::{ConnectionTrait, Schema};
        std::fs::create_dir_all(&config::get_config().common.data_db_dir).unwrap();
        let db = infra::db::get_orm_client_rw().await;
        let schema = Schema::new(db.get_database_backend());
        for mut statement in [
            schema.create_table_from_entity(infra::table::entity::alert_incidents::Entity),
            schema.create_table_from_entity(infra::table::entity::alert_incident_alerts::Entity),
            schema.create_table_from_entity(infra::table::entity::incident_events::Entity),
        ] {
            db.execute(db.get_database_backend().build(statement.if_not_exists()))
                .await
                .unwrap();
        }
        let org = format!("api-oss-{}", uuid::Uuid::new_v4());
        let incident = infra::table::alert_incidents::create(
            &org,
            "P3",
            serde_json::json!({}),
            "alert_id",
            1,
            Some("API incident".into()),
        )
        .await
        .unwrap();
        let path = || Path((org.clone(), incident.id.clone()));
        let actor = || {
            Headers(UserEmail {
                user_id: "authenticated@example.com".into(),
            })
        };
        let response = get_incident(Path(("other-org".into(), incident.id.clone()))).await;
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
        let response = get_incident_events(Path(("other-org".into(), incident.id.clone()))).await;
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
        let response = update_incident(
            Path(("other-org".into(), incident.id.clone())),
            actor(),
            Ok(Json(UpdatePayload::Status {
                status: IncidentStatus::Resolved,
            })),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
        let response = post_incident_comment(
            Path(("other-org".into(), incident.id.clone())),
            actor(),
            Ok(Json(CommentRequest {
                comment: "unauthorized".into(),
            })),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
        let response = update_incident(
            path(),
            actor(),
            Ok(Json(UpdatePayload::Status {
                status: IncidentStatus::Acknowledged,
            })),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let response = post_incident_comment(
            path(),
            actor(),
            Ok(Json(CommentRequest {
                comment: "investigating".into(),
            })),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let events = openobserve_core::alerts::incidents::get_events(&org, &incident.id)
            .await
            .unwrap();
        let serialized = serde_json::to_string(&events).unwrap();
        assert!(serialized.contains("authenticated@example.com"));
        assert!(serialized.contains("investigating"));
        assert!(!serialized.contains("unauthorized"));
        let response = update_incident(
            path(),
            actor(),
            Ok(Json(UpdatePayload::Severity {
                severity: IncidentSeverity::P3,
            })),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["analysis_in_flight"], false);
        assert_eq!(body["severity"], "P3");
        let response = list_incidents(
            Path(org.clone()),
            Ok(Query(ListIncidentsQuery {
                status: Some("acknowledged".into()),
                limit: 50,
                offset: 0,
            })),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["total"], 1);
        let response = get_incident_stats(Path(org.clone())).await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        infra::table::incident_events::delete_by_org(&org)
            .await
            .unwrap();
        infra::table::alert_incidents::delete_by_org(&org)
            .await
            .unwrap();
    }

    #[test]
    fn test_default_limit() {
        assert_eq!(default_limit(), 50);
    }

    #[test]
    fn test_list_incidents_query_defaults() {
        let query = ListIncidentsQuery {
            status: None,
            limit: default_limit(),
            offset: 0,
        };
        assert_eq!(query.limit, 50);
        assert_eq!(query.offset, 0);
        assert!(query.status.is_none());
    }

    #[test]
    fn test_list_incidents_query_with_status() {
        let query = ListIncidentsQuery {
            status: Some("open".to_string()),
            limit: 100,
            offset: 25,
        };
        assert_eq!(query.status.unwrap(), "open");
        assert_eq!(query.limit, 100);
        assert_eq!(query.offset, 25);
    }

    #[test]
    fn test_list_incidents_response_structure() {
        let response = ListIncidentsResponse {
            incidents: vec![],
            total: 0,
        };
        assert_eq!(response.incidents.len(), 0);
        assert_eq!(response.total, 0);
    }

    #[test]
    fn test_list_incidents_response_with_data() {
        let incident = config::meta::alerts::incidents::Incident {
            id: "test-id".to_string(),
            org_id: "default".to_string(),
            status: config::meta::alerts::incidents::IncidentStatus::Open,
            severity: config::meta::alerts::incidents::IncidentSeverity::P1,
            topology_context: None,
            error_tracking: None,
            first_alert_at: 1000,
            last_alert_at: 2000,
            resolved_at: None,
            alert_count: 5,
            title: Some("Test Incident".to_string()),
            assigned_to: None,
            acknowledged_by: None,
            acknowledged_at: None,
            created_at: 1000,
            updated_at: 2000,
            group_values: serde_json::Value::Object(Default::default()),
            key_type: config::meta::alerts::incidents::KeyType::default(),
        };

        let response = ListIncidentsResponse {
            incidents: vec![incident],
            total: 1,
        };
        assert_eq!(response.incidents.len(), 1);
        assert_eq!(response.total, 1);
        assert_eq!(response.incidents[0].id, "test-id");
        assert_eq!(response.incidents[0].alert_count, 5);
    }

    #[test]
    fn test_update_severity_enum() {
        assert_eq!(IncidentSeverity::P1.as_str(), "P1");
        assert_eq!(IncidentSeverity::P2.as_str(), "P2");
        assert_eq!(IncidentSeverity::P3.as_str(), "P3");
        assert_eq!(IncidentSeverity::P4.as_str(), "P4");
    }

    #[test]
    fn test_update_status_enum() {
        assert_eq!(IncidentStatus::Open.as_str(), "open");
        assert_eq!(IncidentStatus::Acknowledged.as_str(), "acknowledged");
        assert_eq!(IncidentStatus::Resolved.as_str(), "resolved");
    }

    #[test]
    fn test_update_payload_title_serialization() {
        let payload = UpdatePayload::Title {
            title: "New Incident Title".to_string(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("New Incident Title"));
        assert!(json.contains("title"));
    }

    #[test]
    fn test_update_payload_severity_serialization() {
        let payload = UpdatePayload::Severity {
            severity: IncidentSeverity::P1,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("P1"));
        assert!(json.contains("severity"));
    }

    #[test]
    fn test_update_payload_status_serialization() {
        let payload = UpdatePayload::Status {
            status: IncidentStatus::Acknowledged,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("acknowledged"));
        assert!(json.contains("status"));
    }

    #[test]
    fn test_update_payload_title_deserialization() {
        let json = r#"{"title":"Critical Production Issue"}"#;
        let payload: UpdatePayload = serde_json::from_str(json).unwrap();
        match payload {
            UpdatePayload::Title { title } => {
                assert_eq!(title, "Critical Production Issue");
            }
            _ => panic!("Expected Title variant"),
        }
    }

    #[test]
    fn test_update_payload_severity_deserialization() {
        let json = r#"{"severity":"P2"}"#;
        let payload: UpdatePayload = serde_json::from_str(json).unwrap();
        match payload {
            UpdatePayload::Severity { severity } => {
                assert_eq!(severity, IncidentSeverity::P2);
            }
            _ => panic!("Expected Severity variant"),
        }
    }

    #[test]
    fn test_update_payload_status_deserialization() {
        let json = r#"{"status":"resolved"}"#;
        let payload: UpdatePayload = serde_json::from_str(json).unwrap();
        match payload {
            UpdatePayload::Status { status } => {
                assert_eq!(status, IncidentStatus::Resolved);
            }
            _ => panic!("Expected Status variant"),
        }
    }

    #[test]
    fn test_update_status_serde_roundtrip() {
        for status in [
            IncidentStatus::Open,
            IncidentStatus::Acknowledged,
            IncidentStatus::Resolved,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: IncidentStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, deserialized);
        }
    }

    #[test]
    fn test_update_severity_serde_roundtrip() {
        for severity in [
            IncidentSeverity::P1,
            IncidentSeverity::P2,
            IncidentSeverity::P3,
            IncidentSeverity::P4,
        ] {
            let json = serde_json::to_string(&severity).unwrap();
            let deserialized: IncidentSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(severity, deserialized);
        }
    }

    #[test]
    fn test_update_severity_equality() {
        assert_eq!(IncidentSeverity::P1, IncidentSeverity::P1);
        assert_ne!(IncidentSeverity::P1, IncidentSeverity::P2);
        assert_ne!(IncidentSeverity::P3, IncidentSeverity::P4);
    }

    #[test]
    fn test_update_status_equality() {
        assert_eq!(IncidentStatus::Open, IncidentStatus::Open);
        assert_ne!(IncidentStatus::Open, IncidentStatus::Acknowledged);
        assert_ne!(IncidentStatus::Acknowledged, IncidentStatus::Resolved);
    }
}
