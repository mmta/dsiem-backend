// ch chan<- event.NormalizedEvent, msq string, msqPrefix string, nodeName string, confDir string, frontend string

use std::{ sync::Arc, time::Duration };
use futures_lite::StreamExt;
use tokio::{ sync::{ broadcast::{ Sender, self }, mpsc }, time::{ interval, timeout } };
use std::str;

use crate::{ event::{ self, NormalizedEvent }, asset::NetworkAssets };
use tracing::{ info, error, debug };
use anyhow::{ Result, Context, anyhow };

const EVENT_SUBJECT: &str = "dsiem_events";
const BP_SUBJECT: &str = "dsiem_overload_signals";

async fn nats_client(nats_url: &str) -> Result<async_nats::Client> {
    let client = async_nats::ConnectOptions
        ::new()
        .event_callback(|event| async move {
            match event {
                async_nats::Event::Disconnected => debug!("nats disconnected"),
                async_nats::Event::Connected => debug!("nats reconnected"),
                async_nats::Event::ClientError(err) =>
                    debug!("nats client error occurred: {}", err),
                other => debug!("nats event happened: {}", other),
            }
        })
        .connect(nats_url).await?;
    Ok(client)
}

pub struct WorkerOpt {
    pub nats_url: String,
    pub event_tx: broadcast::Sender<NormalizedEvent>,
    pub bp_rx: mpsc::Receiver<()>,
    pub cancel_rx: broadcast::Receiver<()>,
    pub hold_duration: u8,
    pub assets: Arc<NetworkAssets>,
}

const NATS_CONNECT_MAX_SECONDS: u64 = 5;
pub struct Worker {}

impl Worker {
    pub async fn start(&self, mut opt: WorkerOpt) -> Result<()> {
        let client = timeout(
            std::time::Duration::from_secs(NATS_CONNECT_MAX_SECONDS),
            nats_client(&opt.nats_url)
        ).await?.context(format!("cannot connect to {}", opt.nats_url))?;

        let mut subscription = client
            .subscribe(EVENT_SUBJECT.into()).await
            .map_err(|e| anyhow!("{:?}", e))
            .context(format!("cannot subscribe to dsiem_events from {}", opt.nats_url))?;

        let mut reset_bp = interval(Duration::from_secs(opt.hold_duration.into()));
        let mut bp_state = false;

        info!("listening for new events");
        loop {
            tokio::select! {
                Some(message) = subscription.next() => {
                    if let Ok(v) = str::from_utf8(&message.payload) {

                        if let Err(e) = self.handle_event_message(&opt.assets, &opt.event_tx, v) {
                            error!("{:?}", e);
                        }
                    } else {
                        error!("an event contain bytes that cant be parsed, skipping it");
                    }
                },
                _ = reset_bp.tick() => {
                    if bp_state {
                        if let Err(err) = client.publish(BP_SUBJECT.into(), "false".into()).await {
                            error!("error sending overload = false signal to frontend: {:?}", err);
                        } else {
                            info!("overload = false signal sent to frontend");
                            bp_state = false;
                        }
                    }
                },
                Some(_) = opt.bp_rx.recv() => {
                    debug!("received under pressure signal from backlogs");
                    reset_bp.reset();
                    if bp_state {
                        debug!("last under pressure signal is still active");
                        continue;
                    } 
                    bp_state = true;
                    if let Err(err) = client.publish(BP_SUBJECT.into(), "true".into()).await {
                        error!("error sending overload = true signal to frontend: {:?}", err);
                    } else {
                        info!("overload = true signal sent to frontend");
                    }                    
                },
                _ = opt.cancel_rx.recv() => {
                    info!("cancel signal received, exiting worker thread");
                    break;
                },
            }
        }
        Ok(())
    }

    fn handle_event_message(
        &self,
        assets: &Arc<NetworkAssets>,
        event_tx: &Sender<event::NormalizedEvent>,
        payload_str: &str
    ) -> Result<()> {
        let res: Result<NormalizedEvent, serde_json::Error> = serde_json::from_str(payload_str);
        if res.is_err() {
            let err_text = format!(
                "cannot parse event from message queue: {:?}, skipping it",
                res.unwrap_err()
            );
            return Err(anyhow!(err_text));
        }
        let e = res.unwrap();
        if !e.valid() {
            let err_text = format!("event {} is not valid, skipping it", e.id);
            return Err(anyhow!(err_text));
        }
        if assets.is_whitelisted(&e.src_ip) {
            debug!(e.id, "src_ip {} is whitelisted, skipping event", e.src_ip);
            return Ok(());
        }
        if let Err(err) = event_tx.send(e.clone()) {
            let err_text = format!("cannot send event {}: {:?}, skipping it", e.id, err);
            return Err(anyhow!(err_text));
        }
        debug!("event {} broadcasted", e.id);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::{ time::sleep, task };
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn test_worker() {
        let mut pty = rexpect
            ::spawn("docker run -p 42222:42222 --rm -it nats -p 42222", None)
            .unwrap();
        pty.exp_string("Server is ready").unwrap();

        let assets = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
        let (event_tx, _) = broadcast::channel::<NormalizedEvent>(5);
        let (cancel_tx, cancel_rx) = broadcast::channel::<()>(5);
        let (bp_tx, bp_rx) = mpsc::channel::<()>(5);
        let opt = WorkerOpt {
            nats_url: "nats://127.0.0.1:42222".to_string(),
            assets,
            event_tx,
            cancel_rx,
            bp_rx,
            hold_duration: 1,
        };

        let _detached = task::spawn(async {
            let w = Worker {};
            _ = w.start(opt).await;
        });

        sleep(Duration::from_millis(3000)).await;
        assert!(logs_contain("listening for new events"));

        _ = bp_tx.send(()).await;
        _ = bp_tx.send(()).await;
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("received under pressure signal from backlogs"));
        assert!(logs_contain("overload = true signal sent to frontend"));
        assert!(logs_contain("last under pressure signal is still active"));

        _ = cancel_tx.send(());
        sleep(Duration::from_millis(1000)).await;
        assert!(logs_contain("cancel signal received"));
    }

    #[tokio::test]
    #[traced_test]
    async fn test_handle_event_message() {
        let assets = Arc::new(NetworkAssets::new(true, Some(vec!["assets".to_string()])).unwrap());
        let (event_tx, mut event_rx) = broadcast::channel::<NormalizedEvent>(1);
        let w = Worker {};

        let res = w.handle_event_message(&assets, &event_tx, "foo");
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("cannot parse event"));

        let mut event = NormalizedEvent::default();
        let payload_str = serde_json::to_string(&event).unwrap();

        let res = w.handle_event_message(&assets, &event_tx, &payload_str);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("is not valid"));

        event.plugin_id = 1001;
        event.plugin_sid = 50001;
        event.src_ip = "192.168.0.2".parse().unwrap();
        let payload_str = serde_json::to_string(&event).unwrap();
        let res = w.handle_event_message(&assets, &event_tx, &payload_str);
        assert!(res.is_ok());
        assert!(logs_contain("whitelisted"));

        let h = task::spawn(async move { event_rx.recv().await });

        event.src_ip = "192.168.0.1".parse().unwrap();
        let payload_str = serde_json::to_string(&event).unwrap();
        let res = w.handle_event_message(&assets, &event_tx, &payload_str);
        assert!(res.is_ok());
        assert!(logs_contain("broadcasted"));

        h.abort();
        _ = h.await;

        let res = w.handle_event_message(&assets, &event_tx, &payload_str);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("cannot send event"));
    }
}