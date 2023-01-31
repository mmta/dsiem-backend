use std::path::PathBuf;

use tokio::sync::{ mpsc::Sender as MpscSender, broadcast::Sender };
use tracing::{ info, debug };

use crate::{ directive::Directive, asset::NetworkAssets, event::NormalizedEvent, utils };

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
    pub bp_tx: MpscSender<bool>,
    pub publisher: Sender<NormalizedEvent>,
}

impl Manager {
    pub fn new(
        test_env: bool,
        directives: Vec<Directive>,
        assets: NetworkAssets,
        hold_duration: u8,
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
            bp_tx,
            publisher,
        };
        Ok(m)
    }
    pub async fn listen(self) -> Result<()> {
        info!("backlog manager started");
        // copy this channel to all directive managers
        let mut set = JoinSet::new();
        for d in self.directives {
            let mut rx = self.publisher.subscribe();
            debug!("listening for directive {}", d.id);
            set.spawn(async move {
                while let Ok(evt) = rx.recv().await {
                    debug!("directive {} received evt: {}", d.id, evt.event_id);
                    // proceed to blogs.manager() in go

                    /* break example
                    i += 1;
                    if i == 3 {
                        break;
                    }
                    */
                }
            });
        }

        while set.join_next().await.is_some() {}
        info!("backlog manager exiting");
        Ok(())
    }
}