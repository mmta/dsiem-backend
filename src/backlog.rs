use std::{ net::IpAddr, collections::HashSet };
use chrono::{ DateTime, Utc };
use serde::Deserialize;
use serde_derive::Serialize;
use tokio::{
    sync::{ broadcast::Receiver, mpsc::Sender, RwLock },
    fs::{ File, OpenOptions, self },
    io::AsyncWriteExt,
};
use tracing::{ info, debug, error, warn, trace };
use crate::{
    event::NormalizedEvent,
    rule::DirectiveRule,
    directive::Directive,
    utils::{ self, generate_id },
    asset::NetworkAssets,
};
use anyhow::{ Result, Context, anyhow };

#[derive(Serialize, Deserialize, Debug, Hash, PartialEq, Eq)]
pub struct CustomData {
    pub label: String,
    pub content: String,
}

#[derive(Serialize)]
pub struct SiemAlarmEvent {
    id: String,
    stage: u8,
    event_id: String,
}

#[derive(Debug)]
pub struct Backlog {
    pub id: String,
    pub title: String,
    pub status: String,
    pub kingdom: String,
    pub category: String,
    pub created_time: i64,
    pub update_time: i64,
    pub status_time: RwLock<i64>,
    pub risk: u8,
    pub risk_class: String,
    pub tag: String,
    pub rules: Vec<DirectiveRule>,
    pub current_stage: u8,
    pub highest_stage: u8,
    pub src_ips: RwLock<HashSet<IpAddr>>,
    pub dst_ips: RwLock<HashSet<IpAddr>>,
    pub custom_data: RwLock<HashSet<CustomData>>,
    // #[serde(skip_serializing, skip_deserializing)]
    pub last_srcport: RwLock<u16>, // copied from event for vuln check
    // #[serde(skip_serializing, skip_deserializing)]
    pub last_dstport: RwLock<u16>, // copied from event for vuln check
    // #[serde(skip_serializing, skip_deserializing)]
    pub all_rules_always_active: bool, // copied from directive
    // #[serde(skip_serializing, skip_deserializing)]
    pub assets: NetworkAssets, // copied from asset
    // #[serde(skip_serializing, skip_deserializing)]
    alarm_events_writer: RwLock<Option<File>>,
    // #[serde(skip_serializing, skip_deserializing)]
    alarm_writer: RwLock<Option<File>>,
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
            status_time: RwLock::new(0),
            risk: 0,
            risk_class: "".to_string(),
            tag: "".to_string(),
            rules: vec![],
            current_stage: 1,
            highest_stage: 1,
            src_ips: RwLock::new(vec![].into_iter().collect()),
            dst_ips: RwLock::new(vec![].into_iter().collect()),
            custom_data: RwLock::new(vec![].into_iter().collect()),
            last_srcport: RwLock::new(0),
            last_dstport: RwLock::new(0),
            all_rules_always_active: false,
            assets: NetworkAssets::default(),
            alarm_events_writer: RwLock::new(None),
            alarm_writer: RwLock::new(None),
        }
    }
}

impl Backlog {
    pub async fn new(d: &Directive, a: NetworkAssets, e: &NormalizedEvent) -> Result<Self> {
        info!(directive_id = d.id, "Creating new backlog");
        let mut backlog = Backlog {
            rules: init_backlog_rules(d, e).context("cannot initialize backlog rule")?,
            current_stage: 1,
            assets: a,
            ..Default::default()
        };
        backlog.all_rules_always_active = d.all_rules_always_active;
        backlog.highest_stage = u8::try_from(backlog.rules.len())?;

        let log_dir = utils::log_dir(false).unwrap();
        fs::create_dir_all(&log_dir).await?;
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(log_dir.join("siem_alarm_events.json")).await?;
        backlog.alarm_events_writer = RwLock::new(Some(file));
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(log_dir.join("siem_alarms.json")).await?;
        backlog.alarm_writer = RwLock::new(Some(file));

        Ok(backlog)
    }
    pub async fn start(&self, mut rx: Receiver<NormalizedEvent>, tx: Sender<bool>, max_delay: i64) {
        debug!(self.id, "enter running state");
        while let Ok(event) = rx.recv().await {
            debug!(self.id, event.id, "event received");
            let res = self.process_new_event(&event, &tx, max_delay).await;
            if res.is_err() {
                error!(self.id, event.id, "{}", res.unwrap_err());
            }
        }
    }

    fn is_time_in_order(&self, ts: &DateTime<Utc>) -> bool {
        let prev_stage_ts = self.rules
            .iter()
            .filter(|v| v.stage < self.current_stage)
            .map(|v| v.end_time)
            .max()
            .unwrap_or_default();
        prev_stage_ts < ts.timestamp()
    }

    fn current_rule(&self) -> Result<&DirectiveRule> {
        self.rules
            .iter()
            .filter(|v| v.stage == self.current_stage)
            .last()
            .ok_or_else(|| anyhow!("cannot locate the current rule"))
    }

    pub async fn process_new_event(
        &self,
        event: &NormalizedEvent,
        bp_tx: &Sender<bool>,
        max_delay: i64
    ) -> Result<()> {
        let curr_rule = self.current_rule()?;

        let reader = curr_rule.sticky_diffdata.read().await;
        let n_string = reader.sdiff_string.len();
        let n_int = reader.sdiff_int.len();

        if !curr_rule.does_event_match(&self.assets, event, true).await {
            // if flag is set, check if event match previous stage
            if self.all_rules_always_active && curr_rule.stage != 1 {
                let prev_rules = self.rules
                    .iter()
                    .filter(|v| v.stage < curr_rule.stage)
                    .collect::<Vec<&DirectiveRule>>();
                for r in prev_rules {
                    if !r.does_event_match(&self.assets, event, true).await {
                        continue;
                    }
                    // event match previous rule, processing it further here
                    // just add the event to the stage, no need to process other steps in processMatchedEvent

                    self.append_and_write_event(event).await?;
                    // also update alarm to sync any changes to customData
                    // b.updateAlarm(evt.ConnID, false, nil);
                    debug!(self.id, event.id, "previous rule consume event");
                    return Ok(());
                    // no need to process further rules
                }
            }
            debug!(self.id, event.id, "event doesnt match");
            return Ok(());
        }
        // event match current rule, processing it further here
        debug!(self.id, event.id, "rule stage {} match event", curr_rule.stage);

        // if stickydiff is set, there must be added member to sdiff_string or sdiff_int
        if !curr_rule.sticky_different.is_empty() {
            let reader = curr_rule.sticky_diffdata.read().await;
            if n_string == reader.sdiff_string.len() && n_int == reader.sdiff_int.len() {
                debug!(
                    self.id,
                    "backlog can't find new unique value in stickydiff field {}",
                    curr_rule.sticky_different
                );
                return Ok(());
            }
        }

        // discard out of order event
        if !self.is_time_in_order(&event.timestamp) {
            warn!(self.id, event.id, "discarded out of order event");
        }

        if self.is_under_pressure(event.rcvd_time, max_delay) {
            warn!(self.id, event.id, "is under pressure");
            let res = bp_tx.try_send(true);
            if res.is_err() {
                warn!(
                    self.id,
                    event.id,
                    "error sending under pressure signal: {}",
                    res.unwrap_err()
                );
            }
        }
        debug!(self.id, event.id, "processing matching event");
        self.process_matched_event(event).await
    }

    async fn process_matched_event(&self, event: &NormalizedEvent) -> Result<()> {
        self.append_and_write_event(event).await
    }

    async fn append_and_write_event(&self, event: &NormalizedEvent) -> Result<()> {
        let curr_rule = self.current_rule()?;
        let mut w = curr_rule.event_ids.write().await;
        w.insert(event.id.clone());
        let mut w = self.src_ips.write().await;
        w.insert(event.src_ip);
        let mut w = self.dst_ips.write().await;
        w.insert(event.dst_ip);
        let mut w = self.custom_data.write().await;
        if !event.custom_data1.is_empty() {
            w.insert(CustomData {
                label: event.custom_label1.clone(),
                content: event.custom_data1.clone(),
            });
        }
        if !event.custom_data2.is_empty() {
            w.insert(CustomData {
                label: event.custom_label2.clone(),
                content: event.custom_data2.clone(),
            });
        }
        if !event.custom_data3.is_empty() {
            w.insert(CustomData {
                label: event.custom_label3.clone(),
                content: event.custom_data3.clone(),
            });
        }
        self.set_ports(event).await?;
        self.set_status_time().await?;
        self.update_siem_alarm_events(event).await?;
        Ok(())
    }

    async fn set_ports(&self, e: &NormalizedEvent) -> Result<()> {
        let mut w = self.last_srcport.write().await;
        *w = e.src_port;
        let mut w = self.last_dstport.write().await;
        *w = e.dst_port;
        Ok(())
    }
    async fn set_status_time(&self) -> Result<()> {
        let mut w = self.status_time.write().await;
        *w = Utc::now().timestamp();
        Ok(())
    }

    async fn update_siem_alarm_events(&self, e: &NormalizedEvent) -> Result<()> {
        let sae = SiemAlarmEvent {
            id: self.id.clone(),
            stage: self.current_stage,
            event_id: e.id.clone(),
        };
        let s = serde_json::to_string(&sae)? + "\n";
        trace!(
            id = sae.id,
            stage = sae.stage,
            event_id = sae.event_id,
            "updating siem_alarm_events"
        );
        let mut binding = self.alarm_events_writer.write().await;
        let w = binding.as_mut().unwrap();
        w.write_all(s.as_bytes()).await?;

        Ok(())
    }

    fn is_under_pressure(&self, rcvd_time: i64, max_delay: i64) -> bool {
        let now = Utc::now().timestamp_nanos();
        now - rcvd_time > max_delay
    }
}

pub fn init_backlog_rules(d: &Directive, e: &NormalizedEvent) -> Result<Vec<DirectiveRule>> {
    let mut result = vec![];
    for (i, rule) in d.rules.iter().enumerate() {
        let mut r = rule.clone();
        if i == 0 {
            r.start_time = e.timestamp.timestamp();
            r.rcvd_time = e.rcvd_time;

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
    Ok(result)
}