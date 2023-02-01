use std::net::IpAddr;

use serde::Deserialize;
use serde_derive::Serialize;
use tokio::sync::{ broadcast::{ Receiver, self }, mpsc::{ self, Sender } };
use tracing::info;
use crate::{
    event::NormalizedEvent,
    rule::DirectiveRule,
    directive::Directive,
    utils::{ self, generate_id },
};
use anyhow::Result;

#[derive(Serialize, Deserialize)]
pub struct CustomData {
    pub label: String,
    pub content: String,
}

#[derive(Serialize, Deserialize)]
pub struct Backlog {
    pub id: String,
    pub title: String,
    pub status: String,
    pub kingdom: String,
    pub category: String,
    pub created_time: u64,
    pub update_time: u64,
    pub status_time: u64,
    pub risk: u8,
    pub risk_class: String,
    pub tag: String,
    pub rules: Vec<DirectiveRule>,
    pub current_stage: u8,
    pub highest_stage: u8,
    pub src_ips: Vec<IpAddr>,
    pub dst_ips: Vec<IpAddr>,
    pub custom_data: Vec<CustomData>,
    #[serde(skip_serializing, skip_deserializing)]
    last_event: Option<NormalizedEvent>,
    #[serde(skip_serializing, skip_deserializing)]
    event_rx: Option<Receiver<NormalizedEvent>>,
    #[serde(skip_serializing, skip_deserializing)]
    bp_tx: Option<Sender<bool>>,
}

impl Default for Backlog {
    fn default() -> Self {
        Backlog {
            id: generate_id(),
            title: "".to_string(),
            status: "".to_string(),
            kingdom: "".to_string(),
            category: "".to_string(),
            created_time: 0,
            update_time: 0,
            status_time: 0,
            risk: 0,
            risk_class: "".to_string(),
            tag: "".to_string(),
            rules: vec![],
            current_stage: 1,
            highest_stage: 1,
            src_ips: vec![],
            dst_ips: vec![],
            custom_data: vec![],
            last_event: None,
            event_rx: None,
            bp_tx: None,
        }
    }
}

impl Backlog {
    pub fn new(
        d: &Directive,
        e: &NormalizedEvent,
        event_rx: Receiver<NormalizedEvent>,
        bp_tx: Sender<bool>
    ) -> Result<Self> {
        info!("Creating new backlog for directive {}", d.id);
        let mut backlog = Backlog {
            rules: init_backlog_rules(d, e),
            current_stage: 1,
            ..Default::default()
        };
        backlog.rules[0].start_time = u64::try_from(e.timestamp.timestamp_micros())?;
        backlog.highest_stage = u8::try_from(backlog.rules.len())?;
        backlog.rules[0].rcvd_time = e.rcvd_time;
        backlog.event_rx = Some(event_rx);
        backlog.bp_tx = Some(bp_tx);
        Ok(backlog)
    }
}

fn init_backlog_rules(d: &Directive, e: &NormalizedEvent) -> Vec<DirectiveRule> {
    let mut result = vec![];
    for (i, rule) in d.rules.iter().enumerate() {
        let mut r = rule.clone();
        if i == 0 {
            // if flag is active, replace ANY and HOME_NET on the first rule with specific addresses from event
            if d.all_rules_always_active {
                if r.from == "ANY" || r.from == "HOME_NET" || r.from == "!HOME_NET" {
                    r.from = e.src_ip.to_string();
                }
                if r.to == "ANY" || r.to == "HOME_NET" || r.to == "!HOME_NET" {
                    r.to = e.dst_ip.to_string();
                }
            }
            // reference isn't allowed on first rule so we'll skip the rest
        } else {
            // for the rest, refer to the referenced stage if its not ANY or HOME_NET or !HOME_NET
            // if the reference is ANY || HOME_NET || !HOME_NET then refer to event if its in the format of
            // :refs
            if let Ok(v) = utils::ref_to_digit(&r.from) {
                let vmin1 = usize::from(v - 1);
                let refs = &d.rules[vmin1].from;
                r.from = if refs != "ANY" && refs != "HOME_NET" && refs != "!HOME_NET" {
                    refs.to_string()
                } else {
                    e.src_ip.to_string()
                };
            }
            if let Ok(v) = utils::ref_to_digit(&r.to) {
                let refs = &d.rules[usize::from(v - 1)].to;
                r.to = if refs != "ANY" && refs != "HOME_NET" && refs != "!HOME_NET" {
                    refs.to_string()
                } else {
                    e.dst_ip.to_string()
                };
            }
            if let Ok(v) = utils::ref_to_digit(&r.port_from) {
                let refs = &d.rules[usize::from(v - 1)].port_from;
                r.port_from = if refs != "ANY" { refs.to_string() } else { e.src_port.to_string() };
            }
            if let Ok(v) = utils::ref_to_digit(&r.port_to) {
                let refs = &d.rules[usize::from(v - 1)].port_to;
                r.port_to = if refs != "ANY" { refs.to_string() } else { e.dst_port.to_string() };
            }

            // references in custom data
            if let Ok(v) = utils::ref_to_digit(&r.custom_data1) {
                let refs = &d.rules[usize::from(v - 1)].custom_data1;
                r.custom_data1 = if refs != "ANY" {
                    refs.to_string()
                } else {
                    e.custom_data1.clone()
                };
            }
            if let Ok(v) = utils::ref_to_digit(&r.custom_data2) {
                let refs = &d.rules[usize::from(v - 1)].custom_data2;
                r.custom_data2 = if refs != "ANY" {
                    refs.to_string()
                } else {
                    e.custom_data2.clone()
                };
            }
            if let Ok(v) = utils::ref_to_digit(&r.custom_data3) {
                let refs = &d.rules[usize::from(v - 1)].custom_data3;
                r.custom_data3 = if refs != "ANY" {
                    refs.to_string()
                } else {
                    e.custom_data3.clone()
                };
            }
        }
        result.push(r);
    }
    result
}