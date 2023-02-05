use std::collections::HashSet;
use std::net::IpAddr;
use anyhow::Result;
use serde::Deserialize;
use super::IntelChecker;
use super::IntelResult;
use async_trait::async_trait;

#[derive(Deserialize, Default)]
struct Config {
    url: String,
}
#[derive(Default)]
pub struct Wise {
    config: Config,
}

#[derive(Deserialize)]
pub struct WiseResult {
    field: String,
    len: u16,
    value: String,
}

#[async_trait]
impl IntelChecker for Wise {
    async fn check_ip(&self, ip: IpAddr) -> Result<HashSet<IntelResult>> {
        let url = self.config.url.replacen("${ip}", &ip.to_string(), 1);

        // convert Wise JS object literal to valid JSON

        let text = reqwest
            ::get(url).await?
            .text().await?
            .replace("field:", "field")
            .replace("len:", "len")
            .replace("value:", "value");

        let res: Vec<WiseResult> = serde_json::from_str(&text)?;
        let mut results: HashSet<IntelResult> = HashSet::new();

        for v in res.iter() {
            // len < 5 is ID or metadata, not the actual result text
            if v.len < 5 {
                continue;
            }

            // Example {field:value} returned is:
            // alienvault.activity:Malicious Host
            let r = IntelResult {
                provider: "Wise".to_owned(),
                term: ip.to_string(),
                result: v.field.clone() + ": " + &v.value,
            };
            results.insert(r);
        }

        Ok(results)
    }

    fn initialize(&mut self, config: String) -> Result<()> {
        let c = serde_json::from_str(&config)?;
        self.config = c;
        Ok(())
    }
}