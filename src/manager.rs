use std::{ sync::Arc, time::Duration };

use tracing::{ info, debug, error };

use crate::{
    directive::Directive,
    asset::NetworkAssets,
    event::NormalizedEvent,
    rule,
    backlog::{ self, Backlog, BacklogState },
    intel::IntelPlugin,
    vuln::VulnPlugin,
};

use anyhow::{ Result, anyhow };
use tokio::{
    task::{ JoinSet, self },
    sync::{ broadcast, mpsc, RwLock },
    time::{ interval, timeout },
};

#[derive(PartialEq, Eq, Hash)]
pub struct ManagerReport {
    pub id: u64,
    pub active_backlogs: usize,
}

pub struct ManagerOpt {
    pub test_env: bool,
    pub directives: Vec<Directive>,
    pub assets: Arc<NetworkAssets>,
    pub intels: Arc<IntelPlugin>,
    pub vulns: Arc<VulnPlugin>,
    pub intel_private_ip: bool,
    pub max_delay: i64,
    pub min_alarm_lifetime: i64,
    pub backpressure_tx: mpsc::Sender<()>,
    pub cancel_tx: broadcast::Sender<()>,
    pub resptime_tx: mpsc::Sender<Duration>,
    pub publisher: broadcast::Sender<NormalizedEvent>,
    pub default_status: String,
    pub default_tag: String,
    pub med_risk_min: u8,
    pub med_risk_max: u8,
    pub report_tx: mpsc::Sender<ManagerReport>,
}
pub struct Manager {
    option: ManagerOpt,
}

impl Manager {
    pub fn new(option: ManagerOpt) -> Result<Manager> {
        let m = Manager {
            option,
        };
        Ok(m)
    }
    pub async fn listen(self, report_interval: u64) -> Result<()> {
        info!("backlog manager started");
        // copy this channel to all directive managers
        let bp_sender = self.option.backpressure_tx.clone();
        let mut set = JoinSet::new();
        for directive in self.option.directives {
            let assets = self.option.assets.clone();
            let intels = self.option.intels.clone();
            let vulns = self.option.vulns.clone();
            let sender = self.option.publisher.clone();
            let default_status = self.option.default_status.clone();
            let default_tag = self.option.default_tag.clone();
            let cancel_tx = self.option.cancel_tx.clone();
            let resptime_tx = self.option.resptime_tx.clone();
            let first_rule = directive.rules
                .iter()
                .filter(|v| v.stage == 1)
                .take(1)
                .last()
                .ok_or_else(|| anyhow!("directive {} doesn't have first stage", directive.id))?
                .clone();

            let bp_sender = bp_sender.clone();
            let report_sender = self.option.report_tx.clone();

            set.spawn(async move {
                let (sid_pairs, taxo_pairs) = rule::get_quick_check_pairs(&directive.rules);
                let contains_pluginrule = !sid_pairs.is_empty();
                let contains_taxorule = !taxo_pairs.is_empty();
                let locked_backlogs: RwLock<Vec<Arc<Backlog>>> = RwLock::new(vec![]);
                let mut upstream = sender.subscribe();
                let mut cancel_rx = cancel_tx.subscribe();
                let (downstream_tx, _) = broadcast::channel(1024);
                let (mgr_delete_tx, mut mgr_delete_rx) = mpsc::channel::<()>(128);

                debug!(directive.id, "listening for event");
                let report_sender = report_sender.clone();
                let mut report = interval(Duration::from_secs(report_interval));
                let mut prev_length = 0;
                // initial
                _ = report_sender.send(ManagerReport {
                    id: directive.id,
                    active_backlogs: prev_length,
                }).await;

                loop {
                    tokio::select! {
                        _ = cancel_rx.recv() => {
                            debug!(directive.id, "cancel signal received, exiting manager thread");
                            break;
                        }
                        _ = report.tick() => {
                            let length = { 
                                let r = locked_backlogs.read().await;
                                r.len()
                            };
                            if length != prev_length && report_sender.try_send(ManagerReport {
                                    id: directive.id,
                                    active_backlogs: length
                                }).is_ok() {
                                prev_length = length;
                            }
                        },                        
                        _ = mgr_delete_rx.recv() => {
                            let mut backlogs = locked_backlogs.write().await;
                            info!(directive.id, "cleaning deleted backlog");
                            backlogs.retain(|x| {
                                let s = x.state.read();
                                *s == BacklogState::Created || *s == BacklogState::Running
                            });
                        },
                        Ok(event) = upstream.recv() => {
                            debug!(directive.id, event.id, "received event");
                            if
                                (contains_pluginrule &&
                                    !rule::quick_check_plugin_rule(&sid_pairs, &event)) ||
                                (contains_taxorule && !rule::quick_check_taxo_rule(&taxo_pairs, &event))
                            {
                                debug!(directive.id, event.id, "failed quick check");
                                continue;
                            }
                    
                            let mut match_found = false;
                            // keep this lock for the entire event recv() loop so the next event will get updated backlogs
                            let mut backlogs = locked_backlogs.write().await;

                            debug!(directive.id, event.id, "total backlogs {}", backlogs.len());

                            if !backlogs.is_empty() {
                                if downstream_tx.send(event.clone()).is_ok() {
                                    debug!(directive.id, event.id, "event sent downstream");
                                    // check the result, break as soon as there's a match
                                    for b in backlogs.iter() {
                                        let mut v = b.found_channel.locked_rx.lock().await;
                                        // timeout is used here since downstream_tx.send() doesn't guarantee there will be a response
                                        // on the found_channel
                                        if timeout(Duration::from_millis(1000), v.changed()).await.is_ok() && *v.borrow() {
                                            match_found = true;
                                            break;
                                        } else {
                                            // timeout or v.borrow() == false
                                        }
                                    }
                                } else {
                                    // this can only happen when there's only 1 backlog, and it has exited it's event receiver, 
                                    // but mgr_delete_rx hasn't run yet before locked_backlogs lock was obtained here.
                                    // it is ok therefore to continue evaluating this event as a potential trigger for a new backlog
                                }
                            }

                            if match_found {
                                debug!(directive.id, event.id, "found existing backlog that consumes the event");
                                continue;
                            }

                            // new backlog, make sure the event match the first rule
                            if !first_rule.does_event_match(&assets, &event, false) {
                                debug!(directive.id, event.id, "event doesn't match first rule");
                                // trace!(" the first rule: {:?}, the event: {:?}", first_rule, &event);
                                continue;
                            }

                            debug!(directive.id, event.id, "creating new backlog");
                            let opt = backlog::BacklogOpt {
                                asset: assets.clone(),
                                bp_tx: bp_sender.clone(),
                                delete_tx: mgr_delete_tx.clone(),
                                intels: intels.clone(),
                                vulns: vulns.clone(),
                                min_alarm_lifetime: self.option.min_alarm_lifetime,
                                default_status: default_status.clone(),
                                default_tag: default_tag.clone(),
                                med_risk_min: self.option.med_risk_min,
                                med_risk_max: self.option.med_risk_max,
                                intel_private_ip: self.option.intel_private_ip,
                                directive: &directive,
                                event: &event,    
                            };

                            let res = backlog::Backlog::new(opt).await;
                            if res.is_err() {
                                error!(directive.id, "cannot create backlog: {}", res.unwrap_err());
                            } else if let Ok(b) = res {
                                let locked = Arc::new(b);
                                let clone = Arc::clone(&locked);
                                backlogs.push(locked);
                                let rx = downstream_tx.subscribe();
                                let max_delay = self.option.max_delay;
                                let resptime_tx = resptime_tx.clone();
                                let _detached = task::spawn(async move {
                                    let w = clone;
                                    if let Err(e) = w.start(rx, &event, resptime_tx, max_delay).await {
                                        error!(
                                            directive.id,
                                            w.id,
                                            "backlog exited with an error: {:?}",
                                            e.to_string()
                                        )
                                    }
                                });
                            }
                        }

                    }
                }
            });
        }

        while set.join_next().await.is_some() {}
        info!("backlog manager exiting");
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{ directive, manager };

    use super::*;
    use tokio::{ time::sleep, task };
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn test_manager() {
        let directives = directive
            ::load_directives(true, Some(vec!["directives".to_string(), "directive5".to_string()]))
            .unwrap();
        let assets = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
        let intels = Arc::new(
            crate::intel::load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap()
        );
        let vulns = Arc::new(
            crate::vuln::load_vuln(true, Some(vec!["intel_vuln".to_string()])).unwrap()
        );
        let (event_tx, _) = broadcast::channel(10);
        let (backpressure_tx, _) = mpsc::channel::<()>(8);
        let (resptime_tx, _) = mpsc::channel::<Duration>(128);
        let (cancel_tx, _) = broadcast::channel::<()>(1);
        let (report_tx, mut report_rx) = mpsc::channel::<manager::ManagerReport>(directives.len());
        let opt = ManagerOpt {
            test_env: true,
            directives,
            assets,
            intels,
            vulns,
            intel_private_ip: false,
            max_delay: 0,
            min_alarm_lifetime: 0,
            backpressure_tx,
            cancel_tx: cancel_tx.clone(),
            resptime_tx,
            publisher: event_tx.clone(),
            default_status: "Open".to_string(),
            default_tag: "Identified Threat".to_string(),
            med_risk_min: 3,
            med_risk_max: 6,
            report_tx,
        };

        let _detached = task::spawn(async {
            let m = Manager::new(opt).unwrap();
            _ = m.listen(1).await;
        });

        let _report_receiver = task::spawn(async move {
            let res = report_rx.recv().await;
            if res.is_some() {
                debug!("report received");
            }
        });

        // test comparing report
        let rpt1 = ManagerReport {
            id: 1,
            active_backlogs: 1,
        };
        let mut rpt2 = ManagerReport {
            id: 1,
            active_backlogs: 1,
        };
        assert!(rpt1 == rpt2);
        rpt2.active_backlogs = 2;
        assert!(rpt1 != rpt2);

        let mut evt = NormalizedEvent {
            plugin_id: 31337,
            plugin_sid: 2,
            custom_label1: "label".to_string(),
            custom_data1: "data".to_string(),
            ..Default::default()
        };

        sleep(Duration::from_millis(1000)).await;

        // unmatched event
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("failed quick check"));

        // matched event but not on the first rule
        evt.plugin_id = 1337;
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("event doesn't match first rule"));

        // matched event 1
        evt.plugin_sid = 1;
        evt.id = "1".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("creating new backlog"));

        // matched event 2
        evt.id = "2".to_string();
        event_tx.send(evt.clone()).unwrap();
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("event sent downstream"));
        assert!(logs_contain("found existing backlog that consumes the event"));

        // matched event 3 to 5
        evt.id = "3".to_string();
        event_tx.send(evt.clone()).unwrap();
        evt.id = "4".to_string();
        event_tx.send(evt.clone()).unwrap();
        evt.id = "5".to_string();
        event_tx.send(evt).unwrap();
        sleep(Duration::from_millis(3000)).await;
        assert!(logs_contain("cleaning deleted backlog"));

        // report tick
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("report received"));

        // cancel signal
        _ = cancel_tx.send(());
        sleep(Duration::from_millis(500)).await;
        assert!(logs_contain("backlog manager exiting"));
    }
}