use std::{ net::IpAddr, collections::HashSet, fs, sync::Arc, fmt, time::Duration };
use moka::sync::Cache;
use anyhow::Result;
use serde::{ Deserialize, Serialize };
use tracing::{ info, debug };
use glob::glob;
use async_trait::async_trait;

use crate::utils;
mod nesd;

const VULN_GLOB: &str = "vuln_*.json";
const VULN_MAX_SECONDS: u64 = 10;

#[derive(Deserialize, Clone, Debug)]
pub struct VulnSource {
    pub name: String,
    #[serde(rename(deserialize = "type"))]
    pub source_type: String,
    pub enabled: bool,
    pub plugin: String,
    pub config: String,
}

#[derive(Deserialize, Debug)]
pub struct VulnSources {
    pub vuln_sources: Vec<VulnSource>,
}

#[derive(Hash, Eq, PartialEq, Default, Serialize, Debug, Clone)]
pub struct VulnResult {
    pub provider: String,
    pub term: String,
    pub result: String,
}

#[async_trait]
pub trait VulnChecker: Send + Sync {
    async fn check_ip_port(&self, ip: IpAddr, port: u16) -> Result<HashSet<VulnResult>>;
    fn initialize(&mut self, config: String) -> Result<()>;
}

pub struct VulnPlugin {
    pub checkers: Arc<Vec<Box<dyn VulnChecker>>>,
    pub vuln_sources: Vec<VulnSource>,
    cache: Cache<String, HashSet<VulnResult>>,
}

impl fmt::Debug for VulnPlugin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.vuln_sources)
    }
}

impl VulnPlugin {
    pub async fn run_checkers(&self, ip: IpAddr, port: u16) -> Result<HashSet<VulnResult>> {
        let mut set = HashSet::new();
        let term = ip.to_string() + ":" + &port.to_string();
        for c in self.checkers.iter() {
            let term = term.clone();
            let res = if let Some(v) = self.cache.get(&term) {
                debug!("returning vuln result from cache for {}", ip);
                v
            } else {
                let v = tokio::time::timeout(
                    Duration::from_secs(VULN_MAX_SECONDS),
                    c.check_ip_port(ip, port)
                ).await??;
                debug!("obtained vuln result for {}", ip);
                v
            };
            set.extend(res.clone());
            self.cache.insert(term, res);
        }
        Ok(set)
    }
}

pub fn load_vuln(test_env: bool) -> Result<VulnPlugin> {
    let cfg_dir = utils::config_dir(test_env, None)?;
    let glob_pattern = cfg_dir.to_string_lossy().to_string() + "/" + VULN_GLOB;
    let mut vulns = vec![];
    let mut checkers: Vec<Box<dyn VulnChecker>> = vec![];
    for file_path in glob(&glob_pattern)?.flatten() {
        info!("reading {:?}", file_path);
        let s = fs::read_to_string(file_path)?;
        let loaded: VulnSources = serde_json::from_str(&s)?;
        for s in loaded.vuln_sources {
            if s.enabled {
                vulns.push(s.clone());
            }
            if s.plugin == "Nesd" {
                let mut w = nesd::Nesd::default();
                w.initialize(s.config)?;
                checkers.push(Box::new(w));
            }
        }
        let len = vulns.len();
        if len > 0 {
            info!("loaded {} vuln plugins", len);
        }
    }

    let cache = Cache::builder()
        // Time to live (TTL): 30 minutes
        .time_to_live(Duration::from_secs(30 * 60))
        // Time to idle (TTI):  5 minutes
        .time_to_idle(Duration::from_secs(5 * 60))
        // Create the cache.
        .build();

    let res = VulnPlugin {
        vuln_sources: vulns,
        checkers: Arc::new(checkers),
        cache,
    };
    Ok(res)
}

#[cfg(test)]
mod test {
    use tokio::join;

    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_vuln() {
        let vulns = load_vuln(true).unwrap();
        debug!("vulns: {:?}", vulns);
        assert!(vulns.vuln_sources.len() == 1); // wise, change this if there's anything else
        let mut set = HashSet::new();
        let ip1: IpAddr = "192.168.0.1".parse().unwrap();
        let port1 = 80;
        let ip2: IpAddr = "1.0.0.1".parse().unwrap();
        let port2 = 25;
        let ip3: IpAddr = "1.0.0.2".parse().unwrap();
        let port3 = 31337;
        set.insert(ip1);
        set.insert(ip2);
        set.insert(ip3);
        let res: Result<HashSet<VulnResult>> = vulns.run_checkers(ip1, port1).await;
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "get request error");

        tokio::spawn(async {
            let mut server = mockito::Server::new_with_port_async(18082).await;
            let _m1 = server
                .mock("GET", "/?ip=1.0.0.1&port=25")
                .with_status(200)
                .with_body(r#"[{"cve":"CVE-2023-007","risk":"Medium","name":"James"}]"#)
                .create_async();
            let _m2 = server
                .mock("GET", "/?ip=192.168.0.1&port=80")
                .with_status(200)
                .with_body(r#"[{"cve":"CVE-2007-007","risk":"Medium","name":"Bond"}]"#)
                .create_async();
            let _m3 = server
                .mock("GET", "/?ip=1.0.0.2&port=31337")
                .with_status(200)
                .with_body(r#"[{"cve":"CVE-2001-418","risk":"Low","name":"Teapot"}]"#)
                .create_async();
            let _m4 = server
                .mock("GET", "/?ip=1.0.0.2&port=25")
                .with_status(200)
                .with_body("no vulnerability found\n")
                .create_async();
            join!(_m1, _m2, _m3, _m4);
        });

        let res1 = vulns.run_checkers(ip1, port1).await.unwrap();
        assert!(!res1.is_empty());
        let res2 = vulns.run_checkers(ip2, port2).await.unwrap();
        assert!(!res2.is_empty());
        let res3 = vulns.run_checkers(ip3, port3).await.unwrap();
        assert!(res3.is_empty());
        let res4 = vulns.run_checkers(ip3, port2).await.unwrap();
        assert!(res4.is_empty());
        // run again to use cache
        let result_set = vulns.run_checkers(ip1, port1).await.unwrap();
        let v = result_set.iter().last().unwrap();
        assert_eq!(v.result, "Medium - Bond (CVE-2007-007)");
    }
}