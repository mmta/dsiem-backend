use std::{ net::IpAddr, collections::HashSet, fs, sync::Arc, fmt, time::Duration };
use moka::sync::Cache;
use anyhow::Result;
use serde::{ Deserialize, Serialize };
use tracing::{ info, trace };
use glob::glob;
use async_trait::async_trait;

use crate::utils;
mod wise;

const INTEL_GLOB: &str = "intel_*.json";
const INTEL_MAX_SECONDS: u64 = 10;

#[derive(Deserialize, Clone)]
pub struct IntelSource {
    pub name: String,
    #[serde(rename(deserialize = "type"))]
    pub source_type: String,
    pub enabled: bool,
    pub plugin: String,
    pub config: String,
}

#[derive(Deserialize)]
pub struct IntelSources {
    pub intel_sources: Vec<IntelSource>,
}

#[derive(Hash, Eq, PartialEq, Default, Serialize, Debug, Clone)]
pub struct IntelResult {
    pub provider: String,
    pub term: String,
    pub result: String,
}

#[async_trait]
pub trait IntelChecker: Send + Sync {
    async fn check_ip(&self, ip: IpAddr) -> Result<HashSet<IntelResult>>;
    fn initialize(&mut self, config: String) -> Result<()>;
}

pub struct IntelPlugin {
    pub checkers: Arc<Vec<Box<dyn IntelChecker>>>,
    pub intel_sources: Vec<IntelSource>,
    cache: Cache<IpAddr, HashSet<IntelResult>>,
}

impl fmt::Debug for IntelPlugin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "n/a")
    }
}

impl IntelPlugin {
    pub async fn run_checkers(
        &self,
        check_private_ip: bool,
        targets: HashSet<IpAddr>
    ) -> Result<HashSet<IntelResult>> {
        let mut set = HashSet::new();
        for c in self.checkers.iter() {
            for ip in targets.iter() {
                if !check_private_ip && !ip_rfc::global(ip) {
                    trace!("skipping private IP {}", ip);
                    continue;
                }
                let res = if let Some(v) = self.cache.get(ip) {
                    trace!("returning intel result from cache for {}", ip);
                    v
                } else {
                    let v = tokio::time::timeout(
                        Duration::from_secs(INTEL_MAX_SECONDS),
                        c.check_ip(*ip)
                    ).await??;
                    trace!("obtained intel result for {}", ip);
                    v
                };
                set.extend(res.clone());
                self.cache.insert(*ip, res);
            }
        }
        Ok(set)
    }
}

pub fn load_intel(test_env: bool) -> Result<IntelPlugin> {
    let cfg_dir = utils::config_dir(test_env)?;
    let glob_pattern = cfg_dir.to_string_lossy().to_string() + "/" + INTEL_GLOB;
    let mut intels = vec![];
    let mut checkers: Vec<Box<dyn IntelChecker>> = vec![];
    for file_path in glob(&glob_pattern)?.flatten() {
        info!("reading {:?}", file_path);
        let s = fs::read_to_string(file_path)?;
        let loaded: IntelSources = serde_json::from_str(&s)?;
        for s in loaded.intel_sources {
            if s.enabled {
                intels.push(s.clone());
            }
            if s.plugin == "Wise" {
                let mut w = wise::Wise::default();
                w.initialize(s.config)?;
                checkers.push(Box::new(w));
            }
        }
        let len = intels.len();
        if len > 0 {
            info!("loaded {} intel plugins", len);
        }
    }

    let cache = Cache::builder()
        // Time to live (TTL): 30 minutes
        .time_to_live(Duration::from_secs(30 * 60))
        // Time to idle (TTI):  5 minutes
        .time_to_idle(Duration::from_secs(5 * 60))
        // Create the cache.
        .build();

    let res = IntelPlugin {
        intel_sources: intels,
        checkers: Arc::new(checkers),
        cache,
    };
    Ok(res)
}