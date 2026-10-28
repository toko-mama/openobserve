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

use config::meta::alerts::incidents::TraceErrorReference;
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Set,
};

use crate::{
    db::{get_orm_client_ro, get_orm_client_rw},
    table::entity::incident_trace_occurrences::{self, Column, Entity},
};

pub async fn insert<C: ConnectionTrait>(
    db: &C,
    org: &str,
    incident: &str,
    id: &str,
    reference: &TraceErrorReference,
) -> Result<bool, sea_orm::DbErr> {
    let model = incident_trace_occurrences::ActiveModel {
        org_id: Set(org.to_owned()),
        incident_id: Set(incident.to_owned()),
        occurrence_id: Set(id.to_owned()),
        trace_id: Set(reference.trace_id.clone()),
        span_id: Set(reference.span_id.clone()),
        stream_name: Set(reference.stream_name.clone()),
        timestamp: Set(reference.timestamp),
    };
    let result = Entity::insert(model)
        .on_conflict(
            sea_orm::sea_query::OnConflict::columns([
                Column::OrgId,
                Column::IncidentId,
                Column::OccurrenceId,
            ])
            .do_nothing()
            .to_owned(),
        )
        .do_nothing()
        .exec_without_returning(db)
        .await?;
    Ok(matches!(result, sea_orm::TryInsertResult::Inserted(count) if count > 0))
}

pub async fn list(
    org: &str,
    incident: &str,
    limit: u64,
    offset: u64,
) -> Result<(Vec<TraceErrorReference>, u64), sea_orm::DbErr> {
    let db = get_orm_client_ro().await;
    let query = Entity::find()
        .filter(Column::OrgId.eq(org))
        .filter(Column::IncidentId.eq(incident));
    let total = query.clone().count(db).await?;
    let rows = query
        .order_by_desc(Column::Timestamp)
        .order_by_desc(Column::OccurrenceId)
        .offset(offset)
        .limit(limit)
        .all(db)
        .await?;
    Ok((
        rows.into_iter()
            .map(|row| TraceErrorReference {
                trace_id: row.trace_id,
                span_id: row.span_id,
                stream_name: row.stream_name,
                timestamp: row.timestamp,
            })
            .collect(),
        total,
    ))
}

pub async fn delete_by_org(org: &str) -> Result<(), sea_orm::DbErr> {
    Entity::delete_many()
        .filter(Column::OrgId.eq(org))
        .exec(get_orm_client_rw().await)
        .await?;
    Ok(())
}
