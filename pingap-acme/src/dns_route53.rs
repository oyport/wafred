use std::time::Duration;

use async_trait::async_trait;
use aws_sdk_route53::{
    Client,
    types::{
        Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet,
        RrType,
    },
};
use tokio::sync::Mutex;

use crate::{AcmeDnsTask, Error, Result};

pub(crate) struct Route53DnsTask {
    client: Client,
    zone_id: Option<String>,
    owned: Mutex<Option<(String, String, String)>>,
}

fn failure(message: &str) -> Error {
    Error::Fail {
        category: "route53".into(),
        message: message.into(),
    }
}

/// Bounded SDK error text for an operator log.
///
/// The ACME failure event persists this message and shows it in the console,
/// so provider URLs are stripped of their query strings (credentials) and the
/// whole text is capped: `AccessDenied`, `NoSuchHostedZone` and a conflicting
/// record set must stay distinguishable instead of collapsing into one generic
/// "TXT change failed" line.
fn describe(error: impl std::fmt::Display) -> String {
    let text = error.to_string().replace(['\n', '\r'], " ");
    let text = crate::lets_encrypt::redact_url_queries(&text);
    let mut bounded: String = text.chars().take(240).collect();
    if bounded.len() < text.len() {
        bounded.push('…');
    }
    bounded
}

fn dns_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn in_zone(name: &str, zone: &str) -> bool {
    name == zone
        || name
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn select_zone<'a>(
    name: &str,
    zones: &'a [(String, String)],
) -> Result<&'a str> {
    let mut matching: Vec<_> = zones
        .iter()
        .filter(|(zone, _)| in_zone(name, zone))
        .collect();
    matching.sort_unstable_by_key(|(zone, _)| std::cmp::Reverse(zone.len()));
    let Some(best) = matching.first() else {
        return Err(failure("no matching public hosted zone"));
    };
    // Duplicate hosted zones can exist for the same name (split tests or an
    // abandoned re-create). Count every match for the selected name instead of
    // trusting the first pair, so an ambiguous account always fails closed.
    let best_name = best.0.as_str();
    if matching
        .iter()
        .filter(|(zone, _)| zone.as_str() == best_name)
        .count()
        > 1
    {
        return Err(failure(
            "multiple public hosted zones match; configure hosted_zone_id",
        ));
    }
    Ok(&best.1)
}

async fn build_client() -> Client {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_route53::config::Region::new("us-east-1"))
        // Retrying a write with an unknown outcome could lose track
        // of which task added the value. Retry rejected conflicts
        // after rereading the record set instead.
        .retry_config(
            aws_sdk_route53::config::retry::RetryConfig::standard()
                .with_max_attempts(1),
        )
        .timeout_config(
            aws_sdk_route53::config::timeout::TimeoutConfig::builder()
                .operation_timeout(Duration::from_secs(20))
                .operation_attempt_timeout(Duration::from_secs(8))
                .build(),
        )
        .load()
        .await;
    let config = aws_sdk_route53::config::Builder::from(&config)
        .endpoint_url(pingap_config::ROUTE53_SERVICE_URL)
        .build();
    Client::from_conf(config)
}

impl Route53DnsTask {
    pub(crate) async fn new(url: &str) -> Result<Self> {
        let zone_id = if url.is_empty() {
            None
        } else {
            pingap_config::parse_route53_service_url(url)
                .map_err(|_| failure("invalid Route 53 DNS configuration"))?
        };
        static CLIENT: tokio::sync::OnceCell<Client> =
            tokio::sync::OnceCell::const_new();
        let client = CLIENT.get_or_init(build_client).await.clone();
        Ok(Self {
            client,
            zone_id,
            owned: Mutex::new(None),
        })
    }

    async fn resolve_zone(&self, name: &str) -> Result<String> {
        let id = if let Some(id) = &self.zone_id {
            id.clone()
        } else {
            let mut zones = Vec::new();
            let mut pages =
                self.client.list_hosted_zones().into_paginator().send();
            while let Some(page) = pages.next().await {
                let page = page.map_err(|err| {
                    failure(&format!(
                        "could not list hosted zones: {}",
                        describe(err)
                    ))
                })?;
                zones.extend(
                    page.hosted_zones()
                        .iter()
                        .filter(|zone| {
                            zone.config()
                                .is_some_and(|config| !config.private_zone())
                        })
                        .map(|zone| {
                            (
                                dns_name(zone.name()),
                                zone.id()
                                    .trim_start_matches("/hostedzone/")
                                    .to_string(),
                            )
                        }),
                );
            }
            select_zone(name, &zones)?.to_owned()
        };
        let result =
            self.client.get_hosted_zone().id(&id).send().await.map_err(
                |err| {
                    failure(&format!(
                        "could not read hosted zone: {}",
                        describe(err)
                    ))
                },
            )?;
        let zone = result
            .hosted_zone()
            .ok_or_else(|| failure("missing hosted zone"))?;
        let zone_name = dns_name(zone.name());
        if !zone.config().is_some_and(|config| !config.private_zone())
            || !in_zone(name, &zone_name)
        {
            return Err(failure(
                "hosted zone must be public and contain the challenge name",
            ));
        }
        {
            let expected = result
                .delegation_set()
                .ok_or_else(|| failure("missing hosted zone delegation"))?;
            let mut expected: Vec<_> = expected
                .name_servers()
                .iter()
                .map(|ns| dns_name(ns))
                .collect();
            let resolver = crate::lets_encrypt::new_txt_resolver()?;
            let lookup = resolver
                .lookup(
                    format!("{zone_name}."),
                    hickory_resolver::proto::rr::RecordType::NS,
                )
                .await
                .map_err(|_| {
                    failure("could not resolve public hosted zone delegation")
                })?;
            use hickory_resolver::proto::rr::RData;
            let mut actual: Vec<_> = lookup
                .answers()
                .iter()
                .filter(|record| {
                    dns_name(&record.name.to_string()) == zone_name
                })
                .filter_map(|record| match &record.data {
                    RData::NS(ns) => Some(dns_name(&ns.to_string())),
                    _ => None,
                })
                .collect();
            // A closer delegation may belong to another AWS account or DNS
            // provider, so it will not appear in our hosted zone listing.
            let mut candidate = name;
            while candidate != zone_name {
                match resolver
                    .lookup(
                        format!("{candidate}."),
                        hickory_resolver::proto::rr::RecordType::NS,
                    )
                    .await
                {
                    Ok(lookup)
                        if lookup.answers().iter().any(|record| {
                            matches!(
                                record.data,
                                RData::CNAME(_) | RData::NS(_)
                            )
                        }) =>
                    {
                        return Err(failure(
                            "challenge is delegated outside the selected zone",
                        ));
                    },
                    Ok(_) => {},
                    Err(error)
                        if error.is_no_records_found()
                            || error.is_nx_domain() => {},
                    Err(_) => {
                        return Err(failure(
                            "could not check for a closer DNS delegation",
                        ));
                    },
                }
                candidate = candidate
                    .split_once('.')
                    .ok_or_else(|| failure("invalid challenge name"))?
                    .1;
            }
            expected.sort_unstable();
            actual.sort_unstable();
            if expected.is_empty() || actual != expected {
                return Err(failure(
                    "public DNS delegation does not match the hosted zone",
                ));
            }
        }
        Ok(id)
    }

    async fn change(
        &self,
        zone: &str,
        name: &str,
        value: &str,
        add: bool,
    ) -> Result<bool> {
        for attempt in 0..4 {
            let records = self
                .client
                .list_resource_record_sets()
                .hosted_zone_id(zone)
                .start_record_name(format!("{name}."))
                .start_record_type(RrType::Txt)
                .max_items(2)
                .send()
                .await
                .map_err(|err| {
                    failure(&format!(
                        "could not read TXT record set: {}",
                        describe(err)
                    ))
                })?;
            let mut sets =
                records.resource_record_sets().iter().filter(|set| {
                    dns_name(set.name()) == name && set.r#type() == &RrType::Txt
                });
            let current = sets.next();
            if sets.next().is_some()
                || current.is_some_and(|set| {
                    set.set_identifier().is_some()
                        || set.alias_target().is_some()
                        || set.traffic_policy_instance_id().is_some()
                        || set.health_check_id().is_some()
                        || set.ttl().is_none()
                })
            {
                return Err(failure("unsupported TXT routing configuration"));
            }
            let Some(batch) = txt_change_batch(current, name, value, add)?
            else {
                return Ok(false);
            };
            let result = self
                .client
                .change_resource_record_sets()
                .hosted_zone_id(zone)
                .change_batch(batch)
                .send()
                .await;
            match result {
                Ok(_) => return Ok(true),
                Err(err)
                    if err.as_service_error().is_some_and(|error| {
                        error.is_invalid_change_batch()
                            || error.is_prior_request_not_complete()
                    }) =>
                {
                    tokio::time::sleep(Duration::from_millis(
                        200 * (attempt + 1),
                    ))
                    .await;
                },
                Err(err) => {
                    return Err(failure(&format!(
                        "TXT change failed: {}",
                        describe(err)
                    )));
                },
            }
        }
        Err(failure("TXT record update did not succeed after retries"))
    }
}

// An exact delete and create in one batch prevents overwriting a concurrent edit.
fn txt_change_batch(
    current: Option<&ResourceRecordSet>,
    name: &str,
    value: &str,
    add: bool,
) -> Result<Option<ChangeBatch>> {
    let mut values =
        current.map_or_else(Vec::new, |set| set.resource_records().to_vec());
    let present = values.iter().any(|record| record.value() == value);
    if present == add {
        return Ok(None);
    }

    let mut changes = Vec::new();
    if let Some(set) = current {
        changes.push(change(ChangeAction::Delete, set.clone())?);
    }
    if add {
        values.push(
            ResourceRecord::builder()
                .value(value)
                .build()
                .map_err(|_| failure("could not build TXT value"))?,
        );
    } else {
        values.retain(|record| record.value() != value);
    }
    if !values.is_empty() {
        let replacement = ResourceRecordSet::builder()
            .name(format!("{name}."))
            .r#type(RrType::Txt)
            .ttl(current.and_then(|set| set.ttl()).unwrap_or(60))
            .set_resource_records(Some(values))
            .build()
            .map_err(|_| failure("could not build TXT record set"))?;
        changes.push(change(ChangeAction::Create, replacement)?);
    }

    let batch = ChangeBatch::builder()
        .set_changes(Some(changes))
        .build()
        .map_err(|_| failure("could not build TXT change batch"))?;
    Ok(Some(batch))
}

fn change(action: ChangeAction, set: ResourceRecordSet) -> Result<Change> {
    Change::builder()
        .action(action)
        .resource_record_set(set)
        .build()
        .map_err(|_| failure("could not build TXT record change"))
}

#[async_trait]
impl AcmeDnsTask for Route53DnsTask {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()> {
        let mut owned = self.owned.lock().await;
        if owned.is_some() {
            return Err(failure("Route 53 task already owns a TXT value"));
        }
        let name = dns_name(domain);
        let zone = tokio::time::timeout(
            Duration::from_secs(60),
            self.resolve_zone(&name),
        )
        .await
        .map_err(|_| failure("hosted zone resolution timed out"))??;
        let value = format!("\"{value}\"");
        if self.change(&zone, &name, &value, true).await? {
            *owned = Some((zone, name, value));
        }
        Ok(())
    }

    async fn done(&self) -> Result<()> {
        let mut owned = self.owned.lock().await;
        if let Some((zone, name, value)) = owned.as_ref() {
            self.change(zone, name, value, false).await?;
            *owned = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_existing_txt_and_ttl_during_add_and_cleanup() {
        let name = "_acme-challenge.example.com";
        let existing = ResourceRecordSet::builder()
            .name(format!("{name}."))
            .r#type(RrType::Txt)
            .ttl(300)
            .resource_records(
                ResourceRecord::builder()
                    .value(r#""unrelated""#)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let apex = r#""apex""#;
        let wildcard = r#""wildcard""#;
        let add_apex = txt_change_batch(Some(&existing), name, apex, true)
            .unwrap()
            .unwrap();
        assert_eq!(add_apex.changes()[0].action(), &ChangeAction::Delete);
        assert_eq!(
            add_apex.changes()[0].resource_record_set(),
            Some(&existing)
        );
        let with_apex = add_apex.changes()[1].resource_record_set().unwrap();
        let add_wildcard =
            txt_change_batch(Some(with_apex), name, wildcard, true)
                .unwrap()
                .unwrap();
        let both = add_wildcard.changes()[1].resource_record_set().unwrap();
        assert_eq!(both.resource_records().len(), 3);
        assert!(
            txt_change_batch(Some(both), name, apex, true)
                .unwrap()
                .is_none()
        );
        let clean_apex = txt_change_batch(Some(both), name, apex, false)
            .unwrap()
            .unwrap();
        let with_wildcard =
            clean_apex.changes()[1].resource_record_set().unwrap();
        let clean_wildcard =
            txt_change_batch(Some(with_wildcard), name, wildcard, false)
                .unwrap()
                .unwrap();
        assert_eq!(
            clean_wildcard.changes()[1].resource_record_set(),
            Some(&existing)
        );
    }

    #[test]
    fn selects_closest_zone_on_label_boundary() {
        let zones = [
            ("example.com".into(), "parent".into()),
            ("child.example.com".into(), "child".into()),
            ("ample.com".into(), "wrong".into()),
        ];
        assert_eq!(
            "child",
            select_zone("_acme-challenge.child.example.com", &zones).unwrap()
        );
        assert!(
            select_zone("_acme-challenge.badexample.com", &zones[..2]).is_err()
        );
        assert!(
            select_zone(
                "child.example.com",
                &[zones[1].clone(), zones[1].clone()]
            )
            .is_err()
        );
    }
}
