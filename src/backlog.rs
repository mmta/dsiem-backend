use std::{
    net::{ IpAddr, Ipv4Addr },
    collections::HashSet,
    ops::Deref,
    time::{ Duration, Instant },
    sync::Arc,
};
use chrono::{ DateTime, Utc };
use metered::{ metered, ResponseTime };
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
    intel::{ IntelPlugin, IntelResult },
    vuln::{ VulnPlugin, VulnResult },
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
    #[serde(rename(serialize = "alarm_id"))]
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
    #[serde(rename(serialize = "alarm_id"))]
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
    pub intel_hits: RwLock<HashSet<IntelResult>>,
    #[serde(skip_serializing_if = "is_locked_data_empty")]
    pub vulnerabilities: RwLock<HashSet<VulnResult>>,
    #[serde(skip_serializing_if = "is_locked_data_empty")]
    pub custom_data: RwLock<HashSet<CustomData>>,
    #[serde(skip_serializing)]
    pub current_stage: RwLock<u8>,
    #[serde(skip_serializing)]
    pub highest_stage: u8,
    #[serde(skip_serializing)]
    pub last_srcport: RwLock<u16>, // copied from event for vuln check
    #[serde(skip_serializing)]
    pub last_dstport: RwLock<u16>, // copied from event for vuln check
    #[serde(skip_serializing)]
    pub all_rules_always_active: bool, // copied from directive
    #[serde(skip_serializing)]
    pub priority: u8, // copied from directive
    #[serde(skip_serializing)]
    pub assets: Arc<NetworkAssets>,
    #[serde(skip_serializing)]
    alarm_events_writer: TokioRwLock<Option<File>>,
    #[serde(skip_serializing)]
    alarm_writer: TokioRwLock<Option<File>>,
    #[serde(skip_serializing)]
    backpressure_tx: Option<Sender<()>>,
    #[serde(skip_serializing)]
    delete_channel: DeleteChannel,
    #[serde(skip_serializing)]
    pub found_channel: FoundChannel,
    #[serde(skip_serializing)]
    pub state: RwLock<BacklogState>,
    #[serde(skip_serializing)]
    pub min_alarm_lifetime: i64,
    #[serde(skip_serializing)]
    pub med_risk_min: u8,
    #[serde(skip_serializing)]
    pub med_risk_max: u8,
    #[serde(skip_serializing)]
    pub intels: Option<Arc<IntelPlugin>>,
    #[serde(skip_serializing)]
    pub vulns: Option<Arc<VulnPlugin>>,
    #[serde(skip_serializing)]
    pub intel_private_ip: bool,
    #[serde(skip_serializing)]
    metrics: Metrics,
}

// This is only used for serialize
fn is_locked_data_empty<T>(s: &RwLock<HashSet<T>>) -> bool {
    let r = s.read();
    r.is_empty()
}

#[derive(Debug)]
struct DeleteChannel {
    tx: tokio::sync::watch::Sender<bool>,
    rx: tokio::sync::watch::Receiver<bool>,
    to_upstream_manager: Option<tokio::sync::mpsc::Sender<()>>,
}

impl Default for DeleteChannel {
    fn default() -> Self {
        let (tx, rx) = watch::channel(false);
        DeleteChannel {
            tx,
            rx,
            to_upstream_manager: None,
        }
    }
}

// for debugging only, to detect when a backlog is out of scope and deleted
impl Drop for DeleteChannel {
    fn drop(&mut self) {
        trace!("Backlog's delete dropped!");
    }
}

#[derive(Debug)]
pub struct FoundChannel {
    tx: tokio::sync::watch::Sender<bool>,
    pub locked_rx: tokio::sync::Mutex<tokio::sync::watch::Receiver<bool>>,
}

impl Default for FoundChannel {
    fn default() -> Self {
        let (tx, rx) = watch::channel(false);
        FoundChannel {
            tx,
            locked_rx: tokio::sync::Mutex::new(rx),
        }
    }
}

pub struct BacklogOpt<'a> {
    pub directive: &'a Directive,
    pub asset: Arc<NetworkAssets>,
    pub intels: Arc<IntelPlugin>,
    pub vulns: Arc<VulnPlugin>,
    pub event: &'a NormalizedEvent,
    pub bp_tx: Sender<()>,
    pub delete_tx: Sender<()>,
    pub min_alarm_lifetime: i64,
    pub default_status: String,
    pub default_tag: String,
    pub med_risk_min: u8,
    pub med_risk_max: u8,
    pub intel_private_ip: bool,
}

#[metered(registry = Metrics)]
impl Backlog {
    pub async fn new(o: BacklogOpt<'_>) -> Result<Self> {
        let mut backlog = Backlog {
            id: utils::generate_id(),
            title: o.directive.name.clone(),
            kingdom: o.directive.kingdom.clone(),
            category: o.directive.category.clone(),
            status: o.default_status,
            tag: o.default_tag,
            intel_private_ip: o.intel_private_ip,

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
        backlog.delete_channel.to_upstream_manager = Some(o.delete_tx);

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

        backlog.intels = Some(o.intels);
        backlog.vulns = Some(o.vulns);

        info!(
            directive_id = o.directive.id,
            backlog.id,
            event_id = o.event.id,
            "new backlog created"
        );
        Ok(backlog)
    }

    async fn handle_expiration(&self) -> Result<()> {
        self.set_rule_status("timeout")?;
        self.update_alarm(false).await?;
        self.delete()
    }

    pub async fn start(
        &self,
        mut rx: Receiver<NormalizedEvent>,
        initial_event: &NormalizedEvent,
        resptime_tx: Sender<Duration>,
        max_delay: i64
    ) -> Result<()> {
        self.process_new_event(initial_event, max_delay).await?;
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
                    {
                        let r = self.state.read();
                        if *r != BacklogState::Running {
                            warn!(self.id, event.id, "event received, but backlog state is not running");
                            continue;
                        }    
                    }
                    debug!(self.id, event.id, "event received");
                    let now = Instant::now();
                    if let Err(e) = self.process_new_event(&event,  max_delay).await {
                        error!(self.id, event.id, "error processing event: {}", e);
                    };
                    _ = resptime_tx.try_send( now.elapsed());
                },  
                _ = delete_rx.changed() => {
                    self.set_state(BacklogState::Stopped);
                    debug!(self.id, "backlog delete signal received");
                    if let Some(v) = &self.delete_channel.to_upstream_manager {
                        if let Err(e) = v.send(()).await {
                            debug!{self.id, "error notifying manager about backlog deletion: {:?}", e}
                        }
                    };
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
        prev_stage_ts <= ts.timestamp()
    }

    pub fn current_rule(&self) -> Result<&DirectiveRule> {
        self.get_rule(None)
    }

    pub fn get_rule(&self, stage: Option<u8>) -> Result<&DirectiveRule> {
        let s = if let Some(v) = stage {
            v
        } else {
            let reader = self.current_stage.read();
            *reader
        };
        self.rules
            .iter()
            .filter(|v| v.stage == s)
            .last()
            .ok_or_else(|| anyhow!("cannot locate the current rule"))
    }

    fn report_to_manager(&self, match_found: bool) -> Result<()> {
        self.found_channel.tx.send(match_found)?;
        Ok(())
    }

    #[measure([ResponseTime])]
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
                debug!(self.id, "checking prev rules because all_rules_always_active is on");
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
                    debug!(self.id, event.id, r.stage, "previous rule match");
                    self.append_and_write_event(event, Some(r.stage)).await?;
                    // also update alarm to sync any changes to customData
                    self.update_alarm(false).await?;
                    debug!(self.id, event.id, r.stage, "previous rule consume event");
                    _ = self.report_to_manager(true);
                    return Ok(());
                    // no need to process further rules
                }
            }
            debug!(self.id, event.id, "event doesn't match");
            // debug!(self.id, "rule: {:?}", curr_rule);
            // debug!(self.id, "event: {:?}", event);
            _ = self.report_to_manager(false);
            return Ok(());
        }

        // if stickydiff is set, there must be added member to sdiff_string or sdiff_int
        if !curr_rule.sticky_different.is_empty() {
            let reader = curr_rule.sticky_diffdata.read();
            if n_string == reader.sdiff_string.len() && n_int == reader.sdiff_int.len() {
                debug!(
                    self.id,
                    "backlog can't find new unique value in stickydiff field {}",
                    curr_rule.sticky_different
                );
                _ = self.report_to_manager(false);
                return Ok(());
            }
        }

        if !self.is_time_in_order(&event.timestamp) {
            warn!(self.id, event.id, "discarded out of order event");
            _ = self.report_to_manager(false);
            return Ok(());
        }

        // event match current rule, processing it further here
        debug!(self.id, event.id, "rule stage {} match event", curr_rule.stage);
        _ = self.report_to_manager(true);

        if self.is_under_pressure(event.rcvd_time, max_delay) {
            warn!(self.id, event.id, "is under pressure");
            if let Some(tx) = &self.backpressure_tx {
                if let Err(e) = tx.try_send(()) {
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
        self.append_and_write_event(event, None).await?;
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
            info!(self.id, "reached max stage and occurrence, deleting backlog");
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

    async fn append_and_write_event(
        &self,
        event: &NormalizedEvent,
        stage: Option<u8>
    ) -> Result<()> {
        let target_rule = self.get_rule(stage)?;
        {
            let ttl_events = target_rule.event_ids.read().len();
            debug!(
                self.id,
                event.id,
                target_rule.stage,
                "appending event {}/{}",
                ttl_events,
                target_rule.occurrence
            );
        }
        {
            let mut w = target_rule.event_ids.write();
            w.insert(event.id.clone());
        }

        const DEFAULT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        {
            let mut w = self.src_ips.write();
            w.insert(event.src_ip);
            if w.len() > 1 && w.contains(&DEFAULT_IP) {
                w.remove(&DEFAULT_IP);
            }
        }
        {
            let mut w = self.dst_ips.write();
            w.insert(event.dst_ip);
            if w.len() > 1 && w.contains(&DEFAULT_IP) {
                w.remove(&DEFAULT_IP);
            }
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
        self.append_siem_alarm_events(event, stage).await?;
        Ok(())
    }

    fn set_ports(&self, e: &NormalizedEvent) {
        if e.src_port != 0 {
            let mut w = self.last_srcport.write();
            *w = e.src_port;
        }
        if e.dst_port != 0 {
            let mut w = self.last_dstport.write();
            *w = e.dst_port;
        }
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
        if max_delay == 0 {
            return false;
        }
        // if rcvd_time is in the future, then this always returns false
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

    async fn append_siem_alarm_events(&self, e: &NormalizedEvent, stage: Option<u8>) -> Result<()> {
        let s = if let Some(v) = stage {
            v
        } else {
            let reader = self.current_stage.read();
            *reader
        };
        let sae = SiemAlarmEvent {
            id: self.id.clone(),
            stage: s,
            event_id: e.id.clone(),
        };
        let s = serde_json::to_string(&sae)? + "\n";
        trace!(
            alarm_id = sae.id,
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

        if check_intvuln {
            if self.intels.is_some() {
                debug!(self.id, "querying threat intel plugins");
                // dont fail alarm update if there's intel check err
                _ = self
                    .check_intel().await
                    .map_err(|e| { error!(self.id, "intel check error: {:?}", e) });
            }
            if self.vulns.is_some() {
                debug!(self.id, "querying vulnerability check plugins");
                // dont fail alarm update if there's intel check err
                _ = self
                    .check_vuln().await
                    .map_err(|e| { error!(self.id, "vuln check error: {:?}", e) });
            }
        }

        let s = serde_json::to_string(&self)? + "\n";
        let mut binding = self.alarm_writer.write().await;
        let w = binding.as_mut().unwrap();
        w.write_all(s.as_bytes()).await?;

        Ok(())
    }

    async fn check_intel(&self) -> Result<()> {
        let intels = self.intels.as_ref().ok_or_else(|| anyhow!("intels is none"))?;
        let mut targets = HashSet::new();
        for s in [&self.src_ips, &self.dst_ips] {
            let r = s.read();
            targets.extend(r.clone());
        }
        let res = intels.run_checkers(self.intel_private_ip, targets).await?;
        let mut w = self.intel_hits.write();
        if res == *w {
            debug!(self.id, "no new intel match found");
            return Ok(());
        }
        let difference = res.difference(&w);
        debug!(self.id, "found {} new intel matches", difference.count());
        *w = res;
        Ok(())
    }

    async fn check_vuln(&self) -> Result<()> {
        let vulns = self.vulns.as_ref().ok_or_else(|| anyhow!("vulns is none"))?;

        let mut vs = VulnSearchTerm::default();
        for r in self.rules.iter() {
            let ips: HashSet<&str> = r.from.split(',').collect();
            let ports: HashSet<&str> = r.port_from.split(',').collect();
            let port = *self.last_srcport.read();
            vs.add(ips, ports, port);
            let ips: HashSet<&str> = r.to.split(',').collect();
            let ports: HashSet<&str> = r.port_to.split(',').collect();
            let port = *self.last_dstport.read();
            vs.add(ips, ports, port);
        }

        let mut combined: HashSet<VulnResult> = HashSet::new();
        for term in vs.terms {
            let ip = term.0;
            let port = term.1;
            debug!(self.id, "vulnerability check for {}:{}", ip, port);
            let s = ip.to_string() + ":" + &port.to_string();
            {
                let r = self.vulnerabilities.read();
                let found = r
                    .iter()
                    .filter(|v| v.term == s)
                    .last();
                if found.is_some() {
                    continue;
                }
            }
            let res = vulns.run_checkers(ip, port).await?;
            combined.extend(res);
        }

        let mut w = self.vulnerabilities.write();
        if combined == *w {
            debug!(self.id, "no new vulnerability match found");
            return Ok(());
        }
        let difference = combined.difference(&w);
        debug!(self.id, "found {} new vulnerability matches", difference.count());
        *w = combined;
        Ok(())
    }
}

#[derive(Default, Debug)]
struct VulnSearchTerm {
    terms: HashSet<(IpAddr, u16)>,
}

impl VulnSearchTerm {
    fn add(&mut self, ip_set: HashSet<&str>, ports: HashSet<&str>, evt_port: u16) {
        for z in ip_set {
            if let Ok(ip) = z.parse::<IpAddr>() {
                if evt_port != 0 {
                    self.terms.insert((ip, evt_port));
                }
                for y in ports.clone() {
                    if let Ok(port) = y.parse::<u16>() {
                        if port != 0 {
                            self.terms.insert((ip, port));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::directive;

    use super::*;
    use chrono::Days;
    use tokio::{ time::sleep, task, sync::{ mpsc, broadcast } };
    use tracing_test::traced_test;

    #[test]
    fn test_vuln_searchterm() {
        let mut vs = VulnSearchTerm::default();
        let mut ipset = HashSet::new();
        ipset.insert("192.168.0.1");
        let mut ports = HashSet::new();
        ports.insert("80");
        let evt_port = 443;
        vs.add(ipset.clone(), ports.clone(), evt_port);
        assert!(vs.terms.len() == 2);
        vs.add(ipset, ports, evt_port);
        assert!(vs.terms.len() == 2);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_backlog() {
        let directives = directive
            ::load_directives(true, Some(vec!["directives".to_string(), "directive5".to_string()]))
            .unwrap();
        let d = directives[0].clone();
        let asset = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
        let intels = Arc::new(
            crate::intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap()
        );
        let vulns = Arc::new(
            crate::vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap()
        );
        let (mgr_delete_tx, _) = mpsc::channel::<()>(128);
        let (event_tx, event_rx) = broadcast::channel(10);
        let (bp_tx, _) = mpsc::channel::<()>(1);
        let (resptime_tx, _resptime_rx) = mpsc::channel::<Duration>(128);

        let now = Utc::now().timestamp_nanos();

        let mut evt = NormalizedEvent {
            plugin_id: 1337,
            plugin_sid: 1,
            id: "1".to_string(),
            src_ip: "192.168.0.1".parse().unwrap(),
            dst_ip: "10.0.0.131".parse().unwrap(),
            src_port: 31337,
            dst_port: 80,
            custom_label1: "label".to_string(),
            custom_data1: "data".to_string(),
            custom_label2: "label".to_string(),
            custom_data2: "data".to_string(),
            custom_label3: "label".to_string(),
            custom_data3: "data".to_string(),
            rcvd_time: now - 10000,
            ..Default::default()
        };

        let evt_cloned = evt.clone();
        let opt = BacklogOpt {
            directive: &d,
            asset,
            intels,
            vulns,
            event: &evt_cloned,
            bp_tx,
            delete_tx: mgr_delete_tx,
            default_status: "Open".to_string(),
            default_tag: "Identified Threat".to_string(),
            min_alarm_lifetime: 0,
            med_risk_min: 3,
            med_risk_max: 6,
            intel_private_ip: true,
        };
        let backlog = Backlog::new(opt).await.unwrap();
        let _detached = task::spawn(async move {
            _ = backlog.start(event_rx, &evt_cloned, resptime_tx, 1).await;
        });

        // these matching event should increase level from 2 to 3 to 4, and raise risk
        evt.id = "2".to_string();
        evt.src_ip = "0.0.0.0".parse().unwrap();
        evt.dst_ip = "0.0.0.0".parse().unwrap();
        event_tx.send(evt.clone()).unwrap();

        evt.id = "3".to_string();
        evt.dst_ip = "10.0.0.131".parse().unwrap();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("risk changed"));
        assert!(logs_contain("stage increased to 4"));

        // event with out of order timestamp
        evt.timestamp = Utc::now().checked_sub_days(Days::new(1)).unwrap();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("discarded out of order event"));

        // these matching event should reach max occurrence for stage 4
        evt.timestamp = Utc::now();
        evt.id = "4".to_string();
        event_tx.send(evt.clone()).unwrap();
        evt.id = "5".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("reached max stage and occurrence"));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_expired() {
        let directives = directive
            ::load_directives(true, Some(vec!["directives".to_string(), "directive5".to_string()]))
            .unwrap();
        let d = directives[0].clone();
        let asset = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
        let intels = Arc::new(
            crate::intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap()
        );
        let vulns = Arc::new(
            crate::vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap()
        );
        let (mgr_delete_tx, _) = mpsc::channel::<()>(128);
        let (_, event_rx) = broadcast::channel(10);
        let (bp_tx, _bp_rx) = mpsc::channel::<()>(8);
        let (resptime_tx, _resptime_rx) = mpsc::channel::<Duration>(128);

        let evt = NormalizedEvent {
            plugin_id: 1337,
            plugin_sid: 1,
            custom_label1: "label".to_string(),
            custom_data1: "data".to_string(),
            ..Default::default()
        };

        let _detached = task::spawn(async move {
            let opt = BacklogOpt {
                directive: &d,
                asset,
                intels,
                vulns,
                event: &evt,
                bp_tx,
                delete_tx: mgr_delete_tx,
                default_status: "Open".to_string(),
                default_tag: "Identified Threat".to_string(),
                min_alarm_lifetime: 0,
                med_risk_min: 3,
                med_risk_max: 6,
                intel_private_ip: false,
            };
            let backlog = Backlog::new(opt).await.unwrap();
            _ = backlog.start(event_rx, &evt, resptime_tx, 0).await;
        });

        // expired
        sleep(Duration::from_millis(13000)).await;
        assert!(logs_contain("backlog expired"));
    }
}