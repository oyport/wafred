// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{AcmeDnsTask, Error, new_dns_http_client};
use async_trait::async_trait;
use chrono::Utc;
use md5::{Digest, Md5};
use reqwest::header::CONTENT_TYPE;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;
use url::Url;

type Result<T, E = Error> = std::result::Result<T, E>;

fn new_error(err: impl ToString) -> Error {
    Error::Fail {
        category: "rainbow_dns".to_string(),
        message: err.to_string(),
    }
}

#[derive(Deserialize)]
struct DomainList {
    rows: Vec<Domain>,
}

#[derive(Deserialize)]
struct Domain {
    id: u64,
    name: String,
}

#[derive(Deserialize)]
struct RecordList {
    rows: Vec<Record>,
}

#[derive(Deserialize)]
struct Record {
    #[serde(rename = "RecordId")]
    record_id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Type")]
    record_type: String,
    #[serde(rename = "Value")]
    value: String,
}

/// Rainbow DNS Manager's API signs the concatenated uid, Unix timestamp, and
/// API key with lowercase MD5. Its `add` response omits the record ID, so the
/// task reads the new TXT record back before ACME validation to clean it up.
pub(crate) struct RainbowDnsTask {
    client: reqwest::Client,
    endpoint: String,
    uid: String,
    key: String,
    record: Mutex<Option<(String, String)>>,
}

impl RainbowDnsTask {
    pub fn new(url: &str) -> Result<Self> {
        if url.trim().is_empty() {
            return Err(new_error("endpoint, uid, and key are required"));
        }
        let info = Url::parse(url).map_err(new_error)?;
        if !matches!(info.scheme(), "http" | "https") {
            return Err(new_error("endpoint must use http or https"));
        }
        if info.host().is_none() {
            return Err(new_error("endpoint host is required"));
        }

        let mut uid = String::new();
        let mut key = String::new();
        for (name, value) in info.query_pairs() {
            match name.as_ref() {
                "uid" => uid = value.into_owned(),
                "key" => key = value.into_owned(),
                _ => {},
            }
        }
        if uid.is_empty() || key.is_empty() {
            return Err(new_error("uid and key are required"));
        }

        // Keep an optional install prefix, but remove query credentials from
        // the API endpoint before sending signed POST bodies.
        let endpoint = format!(
            "{}{}",
            info.origin().ascii_serialization(),
            info.path().trim_end_matches('/')
        );
        Ok(Self {
            client: new_dns_http_client()?,
            endpoint,
            uid,
            key,
            record: Mutex::new(None),
        })
    }

    async fn post(
        &self,
        path: &str,
        fields: &[(&str, String)],
    ) -> Result<Value> {
        let timestamp = Utc::now().timestamp().to_string();
        let message = format!("{}{timestamp}{}", self.uid, self.key);
        let signature = hex::encode(Md5::digest(message.as_bytes()));
        let mut form = vec![
            ("uid".to_string(), self.uid.clone()),
            ("timestamp".to_string(), timestamp),
            ("sign".to_string(), signature),
        ];
        form.extend(
            fields
                .iter()
                .map(|(name, value)| ((*name).to_string(), value.clone())),
        );
        let body = {
            let mut form_encoder =
                url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in &form {
                form_encoder.append_pair(name, value);
            }
            form_encoder.finish()
        };

        let url = format!("{}{path}", self.endpoint.trim_end_matches('/'));
        let response = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .map_err(new_error)?;
        let status = response.status();
        let body = response.text().await.map_err(new_error)?;
        if !status.is_success() {
            return Err(new_error(format!("HTTP {status}: {body}")));
        }

        let value: Value = serde_json::from_str(&body).map_err(new_error)?;
        let code = value.get("code").and_then(|code| {
            code.as_i64().or_else(|| code.as_str()?.parse::<i64>().ok())
        });
        if code.is_some_and(|code| code != 0) {
            let message = value
                .get("msg")
                .and_then(Value::as_str)
                .unwrap_or("API request failed");
            return Err(new_error(message));
        }
        Ok(value)
    }

    async fn find_zone(&self, domain: &str) -> Result<(String, String)> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let search_root = psl::domain_str(&domain)
            .filter(|root| root.contains('.'))
            .ok_or_else(|| new_error(format!("invalid domain: {domain}")))?;
        let response = self
            .post(
                "/api/domain",
                &[
                    ("offset", "0".to_string()),
                    ("limit", "100".to_string()),
                    ("kw", search_root.to_string()),
                ],
            )
            .await?;
        let domains: DomainList =
            serde_json::from_value(response).map_err(new_error)?;
        domains
            .rows
            .into_iter()
            .filter_map(|zone| {
                let zone_name =
                    zone.name.trim_end_matches('.').to_ascii_lowercase();
                let suffix = format!(".{zone_name}");
                let record_name = domain.strip_suffix(&suffix)?;
                if record_name.is_empty() {
                    return None;
                }
                Some((
                    zone_name.len(),
                    zone.id.to_string(),
                    record_name.to_string(),
                ))
            })
            .max_by_key(|(zone_len, _, _)| *zone_len)
            .map(|(_, domain_id, record_name)| (domain_id, record_name))
            .ok_or_else(|| {
                new_error(format!("no managed DNS zone found for {domain}"))
            })
    }

    async fn find_record_id(
        &self,
        domain_id: &str,
        record_name: &str,
        value: &str,
    ) -> Result<String> {
        let response = self
            .post(
                &format!("/api/record/data/{domain_id}"),
                &[
                    ("offset", "0".to_string()),
                    ("limit", "100".to_string()),
                    ("subdomain", record_name.to_string()),
                    ("type", "TXT".to_string()),
                    ("value", value.to_string()),
                ],
            )
            .await?;
        let records: RecordList =
            serde_json::from_value(response).map_err(new_error)?;
        records
            .rows
            .into_iter()
            .find(|record| {
                record.name.trim_end_matches('.').eq_ignore_ascii_case(record_name)
                    && record.record_type.eq_ignore_ascii_case("TXT")
                    && record.value == value
            })
            .map(|record| record.record_id)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                new_error(format!(
                    "TXT record {record_name} was added but its record ID was not returned"
                ))
            })
    }
}

#[async_trait]
impl AcmeDnsTask for RainbowDnsTask {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()> {
        let (domain_id, record_name) = self.find_zone(domain).await?;
        self.post(
            &format!("/api/record/add/{domain_id}"),
            &[
                ("name", record_name.clone()),
                ("type", "TXT".to_string()),
                ("value", value.to_string()),
                ("line", "default".to_string()),
                ("ttl", "600".to_string()),
            ],
        )
        .await?;

        let record_id =
            self.find_record_id(&domain_id, &record_name, value).await?;
        *self.record.lock().await = Some((domain_id, record_id));
        Ok(())
    }

    async fn done(&self) -> Result<()> {
        let record = self.record.lock().await.clone();
        let Some((domain_id, record_id)) = record else {
            return Ok(());
        };
        self.post(
            &format!("/api/record/delete/{domain_id}"),
            &[("recordid", record_id)],
        )
        .await?;
        *self.record.lock().await = None;
        Ok(())
    }
}
