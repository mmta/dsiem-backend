use std::net::IpAddr;

use chrono::prelude::*;
use serde_derive::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct NormalizedEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub sensor: String,
    pub protocol: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub conn_id: u64,
    #[serde(default)]
    pub plugin_id: u64,
    #[serde(default)]
    pub plugin_sid: u64,
    #[serde(default)]
    pub product: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub subcategory: String,
    #[serde(default)]
    pub custom_data1: String,
    #[serde(default)]
    pub custom_label1: String,
    #[serde(default)]
    pub custom_data2: String,
    #[serde(default)]
    pub custom_label2: String,
    #[serde(default)]
    pub custom_data3: String,
    #[serde(default)]
    pub custom_label3: String,
    #[serde(default)]
    pub rcvd_time: u64, // for backpressure control
}

impl NormalizedEvent {
    pub fn valid(&self) -> bool {
        (self.plugin_id != 0 && self.plugin_sid != 0) ||
            (!self.product.is_empty() && !self.category.is_empty())
    }
}