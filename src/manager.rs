use std::sync::Arc;

use futures::StreamExt;
use parking_lot::Mutex;
use tokio::{ sync::{ mpsc::Sender as MpscSender, broadcast::{ Sender, self }, RwLock }, task };
use tracing::{ info, debug, error };

use crate::{
    directive::Directive,
    asset::NetworkAssets,
    event::NormalizedEvent,
    rule,
    backlog::{ self, Backlog, BacklogState },
};

use anyhow::Result;
use tokio::task::JoinSet;

pub struct ManagerOpt {
    pub test_env: bool,
    pub directives: Vec<Directive>,
    pub assets: NetworkAssets,
    pub hold_duration: u8,
    pub max_delay: i64,
    pub min_alarm_lifetime: i64,
    pub backpressure_tx: MpscSender<bool>,
    pub publisher: Sender<NormalizedEvent>,
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
            let sender = self.option.publisher.clone();
            let default_status = self.option.default_status.clone();
            let default_tag = self.option.default_tag.clone();

            if directive.id == 1 || directive.id == 2 {
                continue;
            }
            let bp_sender = bp_sender.clone();
            set.spawn(async move {
                let (sid_pairs, taxo_pairs) = rule::get_quick_check_pairs(&directive.rules);
                let contains_pluginrule = !sid_pairs.is_empty();
                let contains_taxorule = !taxo_pairs.is_empty();
                let mut backlogs: Vec<Arc<RwLock<Backlog>>> = vec![];
                let mut upstream = sender.subscribe();
                let (tx, _) = broadcast::channel(128);
                debug!(directive.id, "listening for event");
                while let Ok(event) = upstream.recv().await {
                    debug!(directive.id, event.id, "received event");
                    if
                        (contains_pluginrule &&
                            !rule::quick_check_plugin_rule(&sid_pairs, &event)) ||
                        (contains_taxorule && !rule::quick_check_taxo_rule(&taxo_pairs, &event))
                    {
                        debug!(directive.id, event.id, "failed quick check");
                        continue;
                    }

                    let match_found = Mutex::new(false);
                    backlogs = futures::stream
                        ::iter(backlogs)
                        .filter_map(|x| async {
                            let binding = x.clone();
                            let reader = binding.read().await;
                            let l = reader.state.read();
                            let result = if *l == BacklogState::Running { Some(x) } else { None };
                            let mut mu_found = match_found.lock();
                            if result.is_some() && !*mu_found {
                                if let Ok(rule) = reader.current_rule() {
                                    if rule.does_event_match(&assets, &event, false) {
                                        *mu_found = true;
                                    }
                                }
                            }
                            result
                        })
                        .collect().await;

                    debug!(directive.id, "total backlogs {}", backlogs.len());
                    for locked in backlogs.iter() {
                        let b = locked.read().await;
                        let res = b.current_rule();
                        match res {
                            Ok(v) => {
                                if v.does_event_match(&assets, &event, false) {
                                    // match_found = true
                                    break;
                                } else {
                                    debug!(
                                        directive.id,
                                        event.id,
                                        "event doesnt match current rule"
                                    );
                                }
                            }
                            _ => {
                                error!(directive.id, b.id, "{}", res.unwrap_err());
                                continue;
                            }
                        }
                    }

                    if match_found.into_inner() {
                        debug!(directive.id, event.id, "found existing backlog");
                    } else {
                        // new backlog
                        debug!(directive.id, event.id, "creating new backlog");
                        let opt = backlog::BacklogOpt {
                            asset: assets.clone(),
                            bp_tx: bp_sender.clone(),
                            min_alarm_lifetime: self.option.min_alarm_lifetime,
                            default_status: default_status.clone(),
                            default_tag: default_tag.clone(),
                            med_risk_min: self.option.med_risk_min,
                            med_risk_max: self.option.med_risk_max,
                            directive: &directive,
                            event: &event,
                        };
                        let res = backlog::Backlog::new(opt).await;
                        if res.is_err() {
                            error!(directive.id, "cannot create backlog: {}", res.unwrap_err());
                        } else if let Ok(b) = res {
                            let locked = Arc::new(RwLock::new(b));
                            let clone = Arc::clone(&locked);
                            backlogs.push(locked);
                            let rx = tx.subscribe();
                            let _detached = task::spawn(async move {
                                let w = clone.read().await;
                                if let Err(e) = w.start(rx, self.option.max_delay).await {
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
                    if let Err(e) = tx.send(event.clone()) {
                        error!(directive.id, event.id, "cant send event downstream: {:?}", e);
                    } else {
                        debug!(directive.id, event.id, "event sent downstream");
                    }
                }
            });
        }

        while set.join_next().await.is_some() {}
        info!("backlog manager exiting");
        Ok(())
    }
}