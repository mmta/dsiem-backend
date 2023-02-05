use std::{ net::IpAddr, collections::HashSet, ops::Deref, time::Duration };
use chrono::{ DateTime, Utc };
use serde::Deserialize;
use serde_derive::Serialize;
use tokio::{
    sync::{ broadcast::Receiver, mpsc::Sender, RwLock as TokioRwLock, watch },
    fs::{ File, OpenOptions, self },
    io::AsyncWriteExt,
    time::interval,
};
use parking_lot::RwLock;
use tracing::{ info, debug, error, warn, trace };
use crate::{
    event::NormalizedEvent,
    rule::DirectiveRule,
    directive::Directive,
    asset::NetworkAssets,
    utils,
};
use anyhow::{ Result, Context, anyhow };

const ALARM_EVENT_LOG: &str = "siem_alarm_events.json";
const ALARM_LOG: &str = "siem_alarms.json";

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

#[derive(Debug, PartialEq, Default)]
pub enum BacklogState {
    #[default]
    Created,
    Running,
    Stopped,
}

// serialize should only for alarm fields
#[derive(Debug, Serialize, Default)]
pub struct Backlog {
    pub id: String,
    pub title: String,
    pub status: String,
    pub tag: String,
    pub kingdom: String,
    pub category: String,
    pub created_time: RwLock<i64>,
    pub update_time: RwLock<i64>,
    pub risk: RwLock<u8>,
    pub risk_class: RwLock<String>,
    pub rules: Vec<DirectiveRule>,
    pub src_ips: RwLock<HashSet<IpAddr>>,
    pub dst_ips: RwLock<HashSet<IpAddr>>,
    pub networks: RwLock<HashSet<String>>,
    #[serde(skip_serializing_if = "is_locked_data_empty")]
    pub custom_data: RwLock<HashSet<CustomData>>,
    #[serde(skip_serializing, skip_deserializing)]
    pub current_stage: RwLock<u8>,
    #[serde(skip_serializing, skip_deserializing)]
    pub highest_stage: u8,
    #[serde(skip_serializing, skip_deserializing)]
    pub last_srcport: RwLock<u16>, // copied from event for vuln check
    #[serde(skip_serializing, skip_deserializing)]
    pub last_dstport: RwLock<u16>, // copied from event for vuln check
    #[serde(skip_serializing, skip_deserializing)]
    pub all_rules_always_active: bool, // copied from directive
    #[serde(skip_serializing, skip_deserializing)]
    pub priority: u8, // copied from directive
    #[serde(skip_serializing, skip_deserializing)]
    pub assets: NetworkAssets, // copied from asset
    #[serde(skip_serializing, skip_deserializing)]
    alarm_events_writer: TokioRwLock<Option<File>>,
    #[serde(skip_serializing, skip_deserializing)]
    alarm_writer: TokioRwLock<Option<File>>,
    #[serde(skip_serializing, skip_deserializing)]
    backpressure_tx: Option<Sender<bool>>,
    #[serde(skip_serializing, skip_deserializing)]
    delete_channel: DeleteChannel,
    #[serde(skip_serializing, skip_deserializing)]
    pub state: RwLock<BacklogState>,
    #[serde(skip_serializing, skip_deserializing)]
    pub min_alarm_lifetime: i64,
    #[serde(skip_serializing, skip_deserializing)]
    pub med_risk_min: u8,
    #[serde(skip_serializing, skip_deserializing)]
    pub med_risk_max: u8,
}

// This is only used for serialize
fn is_locked_data_empty(s: &RwLock<HashSet<CustomData>>) -> bool {
    let r = s.read();
    r.is_empty()
}

#[derive(Debug)]
struct DeleteChannel {
    tx: tokio::sync::watch::Sender<bool>,
    rx: tokio::sync::watch::Receiver<bool>,
}

impl Default for DeleteChannel {
    fn default() -> Self {
        let (tx, rx) = watch::channel(false);
        DeleteChannel {
            tx,
            rx,
        }
    }
}

pub struct BacklogOpt<'a> {
    pub directive: &'a Directive,
    pub asset: NetworkAssets,
    pub event: &'a NormalizedEvent,
    pub bp_tx: Sender<bool>,
    pub min_alarm_lifetime: i64,
    pub default_status: String,
    pub default_tag: String,
    pub med_risk_min: u8,
    pub med_risk_max: u8,
}
impl Backlog {
    pub async fn new(o: BacklogOpt<'_>) -> Result<Self> {
        let mut backlog = Backlog {
            id: utils::generate_id(),
            title: o.directive.name.clone(),
            kingdom: o.directive.kingdom.clone(),
            category: o.directive.category.clone(),
            status: o.default_status,
            tag: o.default_tag,

            rules: o.directive
                .init_backlog_rules(o.event)
                .context("cannot initialize backlog rule")?,
            current_stage: RwLock::new(1),
            priority: o.directive.priority,
            all_rules_always_active: o.directive.all_rules_always_active,
            backpressure_tx: Some(o.bp_tx),
            assets: o.asset,

            min_alarm_lifetime: o.min_alarm_lifetime,
            med_risk_min: o.med_risk_min,
            med_risk_max: o.med_risk_max,
            state: RwLock::new(BacklogState::Created),
            ..Default::default()
        };
        backlog.highest_stage = backlog.rules
            .iter()
            .map(|v| v.stage)
            .max()
            .unwrap_or_default();
        let log_dir = utils::log_dir(false).unwrap();
        fs::create_dir_all(&log_dir).await?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join(ALARM_EVENT_LOG)).await?;
        backlog.alarm_events_writer = TokioRwLock::new(Some(file));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_dir.join(ALARM_LOG)).await?;
        backlog.alarm_writer = TokioRwLock::new(Some(file));

        info!(directive_id = o.directive.id, backlog.id, "new backlog created");

        // debugging
        for r in o.directive.rules.iter() {
            let l = r.event_ids.read();
            debug!(
                backlog.id,
                "referenced rule stage {} event_ids: {}/{}, from: {}, to: {}, start_time: {}",
                r.stage,
                l.len(),
                r.occurrence,
                r.from,
                r.to,
                *r.start_time.read()
            );
        }
        for r in backlog.rules.iter() {
            let l = r.event_ids.read();
            debug!(
                backlog.id,
                "starting rule stage {} event_ids: {}/{}, from: {}, to: {}, start_time: {}",
                r.stage,
                l.len(),
                r.occurrence,
                r.from,
                r.to,
                *r.start_time.read()
            );
        }

        Ok(backlog)
    }

    async fn handle_expiration(&self) -> Result<()> {
        self.set_rule_status("timeout")?;
        self.update_alarm(false).await?;
        self.delete()
    }

    pub async fn start(&self, mut rx: Receiver<NormalizedEvent>, max_delay: i64) -> Result<()> {
        let mut expiration_checker = interval(Duration::from_secs(10));
        let mut delete_rx = self.delete_channel.rx.clone();
        debug!(self.id, "enter running state");
        self.set_state(BacklogState::Running);

        loop {
            tokio::select! {
               _ = expiration_checker.tick() => {
                if let Ok((expired, seconds_left)) = self.is_expired() {
                    if expired {
                        debug!(self.id, "backlog expired, setting last stage status to timeout and deleting it");
                        if let Err(e) = self.handle_expiration().await {
                            debug!{self.id, "error updating status and deleting backlog: {}", e.to_string()}
                        }
                    } else {
                        debug!(self.id, "backlog will expire in {} seconds", seconds_left);
                    }
                }
               },
               Ok(event) = rx.recv() => {
                debug!(self.id, event.id, "event received");
                if let Err(e) = self.process_new_event(&event,  max_delay).await {
                    error!(self.id, event.id, "{}", e);
                }
               },
               _ = delete_rx.changed() => {
                self.set_state(BacklogState::Stopped);
                debug!(self.id, "backlog delete signal received");
                break
               },
            }
        }
        info!(self.id, "exited running state");
        Ok(())
    }

    fn is_expired(&self) -> Result<(bool, i64)> {
        // this calculates in seconds
        let limit = Utc::now().timestamp() - self.min_alarm_lifetime;
        let curr_rule = self.current_rule()?;
        let start = curr_rule.start_time.read();
        let timeout = curr_rule.timeout;
        let max_time = *start + i64::try_from(timeout)?;
        Ok((max_time < limit, max_time - limit))
    }
    fn set_state(&self, s: BacklogState) {
        let mut w = self.state.write();
        *w = s;
    }

    fn is_time_in_order(&self, ts: &DateTime<Utc>) -> bool {
        let reader = self.current_stage.read();
        let prev_stage_ts = self.rules
            .iter()
            .filter(|v| v.stage < *reader)
            .map(|v| {
                let r = v.end_time.read();
                *r
            })
            .max()
            .unwrap_or_default();
        prev_stage_ts < ts.timestamp()
    }

    pub fn current_rule(&self) -> Result<&DirectiveRule> {
        let reader = self.current_stage.read();
        self.rules
            .iter()
            .filter(|v| v.stage == *reader)
            .last()
            .ok_or_else(|| anyhow!("cannot locate the current rule"))
    }

    pub async fn process_new_event(&self, event: &NormalizedEvent, max_delay: i64) -> Result<()> {
        let curr_rule = self.current_rule()?;

        let n_string: usize;
        let n_int: usize;
        {
            let reader = curr_rule.sticky_diffdata.read();
            n_string = reader.sdiff_string.len();
            n_int = reader.sdiff_int.len();
        }

        if !curr_rule.does_event_match(&self.assets, event, true) {
            // if flag is set, check if event match previous stage
            if self.all_rules_always_active && curr_rule.stage != 1 {
                let prev_rules = self.rules
                    .iter()
                    .filter(|v| v.stage < curr_rule.stage)
                    .collect::<Vec<&DirectiveRule>>();
                for r in prev_rules {
                    if !r.does_event_match(&self.assets, event, true) {
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
            debug!(self.id, "{:?}", curr_rule);
            debug!(self.id, "{:?}", event);
            return Ok(());
        }
        // event match current rule, processing it further here
        debug!(self.id, event.id, "rule stage {} match event", curr_rule.stage);

        // if stickydiff is set, there must be added member to sdiff_string or sdiff_int
        if !curr_rule.sticky_different.is_empty() {
            let reader = curr_rule.sticky_diffdata.read();
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
            return Ok(());
        }

        if self.is_under_pressure(event.rcvd_time, max_delay) {
            warn!(self.id, event.id, "is under pressure");
            if let Some(tx) = &self.backpressure_tx {
                if let Err(e) = tx.try_send(true) {
                    warn!(self.id, event.id, "error sending under pressure signal: {}", e);
                }
            }
        }
        debug!(self.id, event.id, "processing matching event");
        self.process_matched_event(event).await
    }

    fn is_stage_reach_max_event_count(&self) -> Result<bool> {
        let curr_rule = self.current_rule()?;
        let reader = curr_rule.event_ids.read();
        let len = reader.len();
        debug!(
            self.id,
            "current rule stage {} event count {}/{}",
            curr_rule.stage,
            len,
            curr_rule.occurrence
        );
        Ok(len >= curr_rule.occurrence)
    }

    fn set_rule_status(&self, status: &str) -> Result<()> {
        let curr_rule = self.current_rule()?;
        let mut w = curr_rule.status.write();
        *w = status.to_owned();
        Ok(())
    }
    fn set_rule_endtime(&self, t: DateTime<Utc>) -> Result<()> {
        let curr_rule = self.current_rule()?;
        let mut w = curr_rule.end_time.write();
        *w = t.timestamp();
        Ok(())
    }
    fn set_rule_starttime(&self, ts: DateTime<Utc>) -> Result<()> {
        let curr_rule = self.current_rule()?;
        let mut w = curr_rule.start_time.write();
        *w = ts.timestamp();
        Ok(())
    }

    fn update_risk(&self) -> Result<bool> {
        let reader = self.src_ips.read();
        let src_value = reader
            .iter()
            .map(|v| self.assets.get_value(v))
            .max()
            .unwrap_or_default();
        let reader = self.dst_ips.read();
        let dst_value = reader
            .iter()
            .map(|v| self.assets.get_value(v))
            .max()
            .unwrap_or_default();

        let prior_risk: u8;
        {
            let reader = self.risk.read();
            prior_risk = *reader.deref();
        }

        let value = std::cmp::max(src_value, dst_value);
        let priority = self.priority;
        let reliability = self.current_rule()?.reliability;
        let risk = (priority * reliability * value) / 25;
        if risk != prior_risk {
            info!(self.id, "risk changed from {} to {}", prior_risk, risk);
            let mut writer = self.risk.write();
            *writer = risk;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn update_risk_class(&self) {
        let mut w = self.risk_class.write();
        let r = self.risk.read();
        let risk = *r;
        *w = if risk < self.med_risk_min {
            "Low".to_string()
        } else if risk >= self.med_risk_min && risk <= self.med_risk_max {
            "Medium".to_string()
        } else {
            "High".to_string()
        };
    }

    fn is_last_stage(&self) -> bool {
        let reader = self.current_stage.read();
        *reader == self.highest_stage
    }

    async fn process_matched_event(&self, event: &NormalizedEvent) -> Result<()> {
        self.append_and_write_event(event).await?;
        // exit early if the newly added event hasnt caused events_count == occurrence
        // for the current stage
        if !self.is_stage_reach_max_event_count()? {
            debug!(self.id, event.id, "stage max event count not yet reached");
            return Ok(());
        }
        // the new event has caused events_count == occurrence
        debug!(self.id, event.id, "stage max event count reached");
        self.set_rule_status("finished")?;
        self.set_rule_endtime(event.timestamp)?;

        // update risk as needed
        let updated = self.update_risk()?;
        if updated {
            self.update_risk_class();
        }

        debug!(self.id, "checking if this is the last stage");
        // if it causes the last stage to reach events_count == occurrence, delete it
        if self.is_last_stage() {
            info!(self.id, "reached max stage and occurrence");
            self.update_alarm(true).await?;
            self.delete()?;
            return Ok(());
        }

        // reach max occurrence, but not in last stage.
        debug!(
            self.id,
            event.id,
            "stage max event count reached, increasing stage and updating alarm"
        );
        // increase stage.
        if self.increase_stage() {
            // set rule startTime for the new stage
            self.set_rule_starttime(event.timestamp)?;
            // stageIncreased, update alarm to publish new stage startTime
            self.update_alarm(true).await?;
        } else {
            error!(self.id, event.id, "stage not increased");
        }

        Ok(())
    }

    fn delete(&self) -> Result<()> {
        self.delete_channel.tx.send(true)?;
        Ok(())
    }

    fn increase_stage(&self) -> bool {
        let mut w = self.current_stage.write();
        if *w < self.highest_stage {
            *w += 1;
            info!(self.id, "stage increased to {}", *w);
            true
        } else {
            info!(self.id, "stage is at the highest level");
            false
        }
    }

    async fn append_and_write_event(&self, event: &NormalizedEvent) -> Result<()> {
        let curr_rule = self.current_rule()?;
        {
            let ttl_events = curr_rule.event_ids.read().len();
            debug!(
                self.id,
                event.id,
                curr_rule.stage,
                "appending event {}/{}",
                ttl_events,
                curr_rule.occurrence
            );
        }
        {
            let mut w = curr_rule.event_ids.write();
            w.insert(event.id.clone());
        }
        {
            let mut w = self.src_ips.write();
            w.insert(event.src_ip);
        }
        {
            let mut w = self.dst_ips.write();
            w.insert(event.dst_ip);
        }
        {
            let mut w = self.custom_data.write();
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
        }

        self.set_ports(event);
        self.set_update_time();
        self.append_siem_alarm_events(event).await?;
        Ok(())
    }

    fn set_ports(&self, e: &NormalizedEvent) {
        let mut w = self.last_srcport.write();
        *w = e.src_port;
        let mut w = self.last_dstport.write();
        *w = e.dst_port;
    }
    fn set_update_time(&self) {
        let mut w = self.update_time.write();
        *w = Utc::now().timestamp();
    }

    fn set_created_time(&self) {
        let is_empty = {
            let r = self.created_time.read();
            *r == 0
        };
        if is_empty {
            let r = self.update_time.read();
            let mut w = self.created_time.write();
            *w = *r;
        }
    }

    fn is_under_pressure(&self, rcvd_time: i64, max_delay: i64) -> bool {
        let now = Utc::now().timestamp_nanos();
        now - rcvd_time > max_delay
    }

    fn update_networks(&self) {
        let mut w = self.networks.write();
        for v in [&self.src_ips, &self.dst_ips] {
            let r = v.read();
            for ip in r.iter() {
                if let Some(v) = self.assets.get_asset_networks(ip) {
                    for x in v {
                        w.insert(x);
                    }
                }
            }
        }
    }

    async fn append_siem_alarm_events(&self, e: &NormalizedEvent) -> Result<()> {
        let sae: SiemAlarmEvent;
        {
            let reader = self.current_stage.read();
            sae = SiemAlarmEvent {
                id: self.id.clone(),
                stage: *reader,
                event_id: e.id.clone(),
            };
        }
        let s = serde_json::to_string(&sae)? + "\n";
        trace!(
            id = sae.id,
            stage = sae.stage,
            event_id = sae.event_id,
            "appending siem_alarm_events"
        );
        let mut binding = self.alarm_events_writer.write().await;
        let w = binding.as_mut().unwrap();
        w.write_all(s.as_bytes()).await?;

        Ok(())
    }

    async fn update_alarm(&self, check_intvuln: bool) -> Result<()> {
        if *self.risk.read() == 0 {
            trace!(self.id, "risk is zero, skip updating alarm");
            return Ok(());
        }
        debug!(self.id, check_intvuln, "updating alarm");
        self.set_created_time();
        self.update_networks();

        let s = serde_json::to_string(&self)? + "\n";
        let mut binding = self.alarm_writer.write().await;
        let w = binding.as_mut().unwrap();
        w.write_all(s.as_bytes()).await?;

        Ok(())

        /* postponed
        if xc.IntelEnabled && checkIntelVuln {
            // do intel check in the background
            asyncIntelCheck(a, connID, intelCheckPrivateIP, tx)
        }
    
        if xc.VulnEnabled && checkIntelVuln {
            // do vuln check in the background
            asyncVulnCheck(a, lastSrcPort, lastDstPort, connID, tx)
        }
        */
    }
}