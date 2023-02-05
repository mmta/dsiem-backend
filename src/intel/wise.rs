use std::net::IpAddr;
use anyhow::Result;
use serde::Deserialize;
use super::IntelChecker;
use super::IntelResult;

#[derive(Deserialize, Default)]
struct Config {
    url: String,
}
#[derive(Default)]
pub struct Wise {
    config: Config,
}

impl IntelChecker for Wise {
    fn check_ip(&self, ip: IpAddr) -> Result<IntelResult> {
        Ok(IntelResult::default())
    }

    fn initialize(&mut self, config: String) -> Result<()> {
        let c = serde_json::from_str(&config)?;
        self.config = c;
        Ok(())
    }
}