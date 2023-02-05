use std::{ net::IpAddr, str::FromStr };

use chrono::prelude::*;
use serde_derive::Deserialize;

#[derive(Deserialize, Clone, Debug)]
pub struct NormalizedEvent {
    #[serde(rename(deserialize = "event_id"))]
    pub id: String,
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
    pub rcvd_time: i64, // for backpressure control
}

impl Default for NormalizedEvent {
    fn default() -> Self {
        NormalizedEvent {
            id: "".to_owned(),
            timestamp: Utc::now(),
            src_ip: IpAddr::from_str("0.0.0.0").unwrap(),
            dst_ip: IpAddr::from_str("0.0.0.0").unwrap(),
            src_port: 0,
            dst_port: 0,
            sensor: "".to_owned(),
            protocol: "".to_owned(),
            title: "".to_owned(),
            conn_id: 0,
            plugin_id: 0,
            plugin_sid: 0,
            product: "".to_owned(),
            category: "".to_owned(),
            subcategory: "".to_owned(),
            custom_data1: "".to_owned(),
            custom_label1: "".to_owned(),
            custom_data2: "".to_owned(),
            custom_label2: "".to_owned(),
            custom_data3: "".to_owned(),
            custom_label3: "".to_owned(),
            rcvd_time: 0,
        }
    }
}

impl NormalizedEvent {
    pub fn valid(&self) -> bool {
        (self.plugin_id != 0 && self.plugin_sid != 0) ||
            (!self.product.is_empty() && !self.category.is_empty())
    }
}