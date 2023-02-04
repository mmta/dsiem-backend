/* postponed

use std::net::IpAddr;
use anyhow::Result;
pub struct IntelResult {
    pub provider: String,
    pub term: String,
    pub result: String,
}
pub trait IntelChecker {
    fn check_ip(&self, ip: IpAddr) -> Result<IntelResult>;
    fn initialize(config: String) -> Result<()>;
}

pub struct VulnResult {
    pub provider: String,
    pub term: String,
    pub result: String,
}

pub trait VulnChecker {
    fn check_ip_port(&self, ip: IpAddr, port: u16) -> Result<VulnResult>;
    fn initialize(config: String) -> Result<()>;
}
*/
