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

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Alias::new("incident_trace_occurrences"))
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Alias::new("org_id"))
                            .string_len(256)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("incident_id"))
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("occurrence_id"))
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("trace_id"))
                            .string_len(128)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("span_id"))
                            .string_len(128)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("stream_name"))
                            .string_len(256)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("timestamp"))
                            .big_integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(Alias::new("org_id"))
                            .col(Alias::new("incident_id"))
                            .col(Alias::new("occurrence_id")),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("incident_trace_occurrences_page")
                    .table(Alias::new("incident_trace_occurrences"))
                    .col(Alias::new("org_id"))
                    .col(Alias::new("incident_id"))
                    .col(Alias::new("timestamp"))
                    .col(Alias::new("occurrence_id"))
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Alias::new("incident_trace_occurrences"))
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn occurrence_migration_is_idempotent_and_reversible() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let manager = SchemaManager::new(&db);
        Migration.up(&manager).await.unwrap();
        Migration.up(&manager).await.unwrap();
        assert!(
            manager
                .has_table("incident_trace_occurrences")
                .await
                .unwrap()
        );
        Migration.down(&manager).await.unwrap();
        assert!(
            !manager
                .has_table("incident_trace_occurrences")
                .await
                .unwrap()
        );
    }
}
