use std::{ path::PathBuf, sync::Arc };

use tokio::{ sync::{ mpsc::Sender as MpscSender, broadcast::{ Sender, self }, RwLock }, task };
use tracing::{ info, debug, error };

use crate::{
    directive::Directive,
    asset::NetworkAssets,
    event::NormalizedEvent,
    utils,
    rule,
    backlog::{ self, Backlog },
};

use anyhow::Result;
use tokio::task::JoinSet;

const ALARM_EVENT_LOG: &str = "siem_alarm_events.json";
const ALARM_LOG: &str = "siem_alarms.json";

pub struct Manager {
    pub alarm_event_log: PathBuf,
    pub alarm_log: PathBuf,
    pub directives: Vec<Directive>,
    pub assets: NetworkAssets,
    pub hold_duration: u8,
    pub max_delay: i64,
    pub bp_tx: MpscSender<bool>,
    pub publisher: Sender<NormalizedEvent>,
}

impl Manager {
    pub fn new(
        test_env: bool,
        directives: Vec<Directive>,
        assets: NetworkAssets,
        hold_duration: u8,
        max_delay: i64,
        bp_tx: MpscSender<bool>,
        publisher: Sender<NormalizedEvent>
    ) -> Result<Manager> {
        let d = utils::config_dir(test_env)?;

        let m = Manager {
            alarm_event_log: d.join("logs").join(ALARM_EVENT_LOG),
            alarm_log: d.join("logs").join(ALARM_LOG),
            directives,
            assets,
            hold_duration,
            max_delay,
            bp_tx,
            publisher,
        };
        Ok(m)
    }
    pub async fn listen(self) -> Result<()> {
        info!("backlog manager started");
        // copy this channel to all directive managers
        let mut set = JoinSet::new();
        for directive in self.directives {
            let assets = self.assets.clone();
            let sender = self.publisher.clone();
            let bp_sender = self.bp_tx.clone();

            if directive.id == 1 || directive.id == 2 {
                continue;
            }
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

                    let mut match_found = false;
                    debug!(directive.id, "total backlogs {}", backlogs.len());
                    for locked in backlogs.iter() {
                        let b = locked.read().await;
                        let res = b.current_rule();
                        if res.is_err() {
                            error!(directive.id, b.id, "{}", res.unwrap_err());
                            continue;
                        }
                        {
                            let r = b.current_stage.read();
                            debug!(
                                directive.id,
                                b.id,
                                stage = *r,
                                "about to check existing backlog"
                            );
                        }
                        if res.unwrap().does_event_match(&assets, &event, false) {
                            match_found = true;
                            break;
                        }
                    }

                    if match_found {
                        debug!(directive.id, event.id, "found existing backlog");
                    } else {
                        // new backlog
                        debug!(directive.id, event.id, "creating new backlog");
                        let res = backlog::Backlog::new(&directive, assets.clone(), &event).await;
                        if res.is_err() {
                            error!(directive.id, "cannot create backlog: {}", res.unwrap_err());
                        } else if let Ok(b) = res {
                            let locked = Arc::new(RwLock::new(b));
                            let clone = Arc::clone(&locked);
                            backlogs.push(locked);
                            let rx = tx.subscribe();
                            let bp_sender = bp_sender.clone();

                            let _detached = task::spawn(async move {
                                let w = clone.read().await;
                                w.start(rx, bp_sender, self.max_delay).await
                            });
                        }
                    }
                    let res = tx.send(event.clone());
                    if res.is_err() {
                        error!(
                            directive.id,
                            event.id,
                            "cant send event downstream: {:?}",
                            res.unwrap_err()
                        );
                    }
                }
            });
        }

        while set.join_next().await.is_some() {}
        info!("backlog manager exiting");
        Ok(())
    }
}