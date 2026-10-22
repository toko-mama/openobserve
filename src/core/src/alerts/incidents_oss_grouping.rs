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

use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Grouping {
    pub values: BTreeMap<String, String>,
    pub alert_fallback: bool,
}

impl Grouping {
    pub fn key(&self, org_id: &str) -> String {
        let mut parts = vec![org_id.to_string(), self.alert_fallback.to_string()];
        for (name, value) in &self.values {
            parts.push(name.clone());
            parts.push(value.clone());
        }
        parts
            .iter()
            .map(|part| format!("{}:{part}", part.len()))
            .collect()
    }
}

pub(crate) fn grouping(
    alert_id: &str,
    fields: &[String],
    labels: &BTreeMap<String, String>,
) -> Grouping {
    let values: Option<BTreeMap<String, String>> = fields
        .iter()
        .map(|field| {
            labels
                .get(field)
                .filter(|value| !value.trim().is_empty())
                .map(|value| (field.clone(), value.clone()))
        })
        .collect();
    match values {
        Some(values) if !values.is_empty() => Grouping {
            values,
            alert_fallback: false,
        },
        _ => Grouping {
            values: BTreeMap::from([("alert_id".into(), alert_id.into())]),
            alert_fallback: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_grouping_is_stable_and_isolates_organization_and_alert() {
        let a = grouping("alert-a", &[], &BTreeMap::new());
        assert_eq!(a.key("org-a"), a.key("org-a"));
        assert_ne!(a.key("org-a"), a.key("org-b"));
        assert_ne!(
            a.key("org-a"),
            grouping("alert-b", &[], &BTreeMap::new()).key("org-a")
        );
    }

    #[test]
    fn explicit_fields_match_across_alerts_independent_of_order() {
        let labels = BTreeMap::from([
            ("service".into(), "api".into()),
            ("env".into(), "prod".into()),
        ]);
        let a = grouping("a", &["service".into(), "env".into()], &labels);
        let b = grouping(
            "b",
            &["env".into(), "service".into(), "service".into()],
            &labels,
        );
        assert!(!a.alert_fallback);
        assert_eq!(a.key("org"), b.key("org"));
        assert_eq!(a.values.len(), 2);
    }

    #[test]
    fn missing_or_empty_field_falls_back_to_alert_identity() {
        let labels = BTreeMap::from([("service".into(), "api".into()), ("env".into(), "".into())]);
        assert_eq!(
            grouping("a", &["missing".into()], &labels),
            grouping("a", &[], &labels)
        );
        assert_eq!(
            grouping("a", &["service".into(), "env".into()], &labels),
            grouping("a", &[], &labels)
        );
    }

    #[test]
    fn keys_include_field_names_and_unambiguous_boundaries() {
        let a = grouping(
            "a",
            &["service".into()],
            &BTreeMap::from([("service".into(), "api".into())]),
        );
        let b = grouping(
            "a",
            &["host".into()],
            &BTreeMap::from([("host".into(), "api".into())]),
        );
        assert_ne!(a.key("org"), b.key("org"));
        let a = grouping(
            "a",
            &["x".into(), "y".into()],
            &BTreeMap::from([("x".into(), "a|y=b".into()), ("y".into(), "c".into())]),
        );
        let b = grouping(
            "a",
            &["x".into(), "y".into()],
            &BTreeMap::from([("x".into(), "a".into()), ("y".into(), "b|y=c".into())]),
        );
        assert_ne!(a.key("org"), b.key("org"));
    }
}
