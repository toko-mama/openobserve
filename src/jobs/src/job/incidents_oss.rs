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

use std::time::Duration;

pub async fn run() {
    let cfg = config::get_config();
    if !cfg.oss_incidents.enabled || cfg.oss_incidents.auto_resolve_timeout_secs == 0 {
        return;
    }
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        if let Err(error) = openobserve_core::alerts::incidents::resolve_stale().await {
            log::error!("[OSS incidents] Failed to resolve inactive incidents: {error}");
        }
    }
}
