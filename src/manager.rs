use std::{ sync::Arc, time::Duration };

use tracing::{ info, debug, error };

use crate::{
    directive::Directive,
    asset::NetworkAssets,
    event::NormalizedEvent,
    rule,
    backlog::{ self, Backlog, BacklogState },
    intel::IntelPlugin,
};

use anyhow::Result;
use tokio::{ task::{ JoinSet, self }, sync::{ broadcast, mpsc, Mutex } };

pub struct ManagerOpt {
    pub test_env: bool,
    pub directives: Vec<Directive>,
    pub assets: Arc<NetworkAssets>,
    pub intels: Arc<IntelPlugin>,
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
    pub async fn listen(self) -> Result<()> {
        info!("backlog manager started");
        // copy this channel to all directive managers
        let bp_sender = self.option.backpressure_tx.clone();
        let mut set = JoinSet::new();
        for directive in self.option.directives {
            let assets = self.option.assets.clone();
            let intels = self.option.intels.clone();
            let sender = self.option.publisher.clone();
            let default_status = self.option.default_status.clone();
            let default_tag = self.option.default_tag.clone();
            let cancel_tx = self.option.cancel_tx.clone();
            let resptime_tx = self.option.resptime_tx.clone();

            if directive.id == 1 || directive.id == 2 {
                continue;
            }
            let bp_sender = bp_sender.clone();
            set.spawn(async move {
                let (sid_pairs, taxo_pairs) = rule::get_quick_check_pairs(&directive.rules);
                let contains_pluginrule = !sid_pairs.is_empty();
                let contains_taxorule = !taxo_pairs.is_empty();
                let locked_backlogs: Mutex<Vec<Arc<Backlog>>> = Mutex::new(vec![]);
                let mut upstream = sender.subscribe();
                let mut cancel_rx = cancel_tx.subscribe();
                let (downstream_tx, _) = broadcast::channel(1024);
                let (mgr_delete_tx, mut mgr_delete_rx) = mpsc::channel::<()>(128);
                debug!(directive.id, "listening for event");

                loop {
                    tokio::select! {
                        _ = cancel_rx.recv() => {
                            info!("cancel signal received, exiting manager thread");
                            break;
                        }
                        _ = mgr_delete_rx.recv() => {
                            debug!(directive.id, "cleaning deleted backlog");
                            let mut backlogs = locked_backlogs.lock().await;
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
                            let mut backlogs = locked_backlogs.lock().await;
                            debug!(directive.id, "total backlogs {}", backlogs.len());
                    
                            for b in backlogs.iter() {
                                if let Ok(rule) = b.current_rule() {
                                    if rule.does_event_match(&assets, &event, false) {
                                        match_found = true;
                                        break;
                                    } else {
                                        debug!(directive.id, event.id, "event doesnt match current rule");
                                    }
                                } else {
                                    error!(directive.id, b.id, "cannot get current rule");
                                    continue;
                                }
                            }
                    
                            if match_found {
                                debug!(directive.id, event.id, "found existing backlog");
                            } else {
                                // new backlog
                                debug!(directive.id, event.id, "creating new backlog");
                                let opt = backlog::BacklogOpt {
                                    asset: assets.clone(),
                                    bp_tx: bp_sender.clone(),
                                    delete_tx: mgr_delete_tx.clone(),
                                    intel: intels.clone(),
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
                                        if let Err(e) = w.start(rx, resptime_tx, max_delay).await {
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
                            if let Err(e) = downstream_tx.send(event.clone()) {
                                error!(directive.id, event.id, "cant send event downstream: {:?}", e);
                            } else {
                                debug!(directive.id, event.id, "event sent downstream");
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