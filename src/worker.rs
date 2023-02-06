// ch chan<- event.NormalizedEvent, msq string, msqPrefix string, nodeName string, confDir string, frontend string

use std::{ fs::File, io::Write, sync::Arc, time::Duration };
use futures::StreamExt;
use tokio::{ sync::{ broadcast::{ Sender, self }, oneshot, mpsc }, time::interval };
use std::str;

use crate::{ utils, event::{ self, NormalizedEvent }, asset::NetworkAssets };
use serde::Deserialize;
use tracing::{ info, error, debug };
use anyhow::{ Result, Context, anyhow };

const EVENT_SUBJECT: &str = "dsiem_events";
const BP_SUBJECT: &str = "dsiem_overload_signals";

#[derive(Deserialize)]
struct ConfigFile {
    filename: String,
}
#[derive(Deserialize)]
struct ConfigFiles {
    files: Vec<ConfigFile>,
}

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
    pub frontend_url: String,
    pub nats_url: String,
    pub node_name: String,
    pub event_tx: broadcast::Sender<NormalizedEvent>,
    pub bp_rx: mpsc::Receiver<()>,
    pub ready_tx: oneshot::Sender<()>,
    pub cancel_rx: broadcast::Receiver<()>,
    pub hold_duration: u8,
    pub assets: Arc<NetworkAssets>,
}

pub async fn start_worker(mut opt: WorkerOpt) -> Result<()> {
    let config_dir = utils::config_dir(false)?;
    download_config_files(
        config_dir.to_string_lossy().to_string(),
        opt.frontend_url,
        opt.node_name
    ).await?;
    let client = nats_client(&opt.nats_url).await?;

    let mut subscription = client
        .subscribe(EVENT_SUBJECT.into()).await
        .map_err(|e| anyhow!("{:?}", e))
        .context(format!("cannot subscribe to dsiem_events from {}", opt.nats_url))?;

    let mut reset_bp = interval(Duration::from_secs(opt.hold_duration.into()));
    let mut bp_state = false;

    info!("worker listening for new events");
    opt.ready_tx.send(()).map_err(|_| anyhow!("cannot send ready signal"))?;

    loop {
        tokio::select! {
            Some(message) = subscription.next() => {
                if let Ok(v) = str::from_utf8(&message.payload) {
                    if let Err(e) = handle_event_message(&opt.assets, &opt.event_tx, v) {
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

async fn list_config_files(frontend_url: String) -> Result<Vec<ConfigFile>> {
    debug!("listing config files from {}", frontend_url);
    let resp = reqwest
        ::get(frontend_url.clone() + "/config/").await
        .context("cannot get a list of config files from frontend")?;
    let text = resp.text().await.context("cannot parse response for request to list config files")?;
    let c: ConfigFiles = serde_json::from_str(&text)?;
    Ok(c.files)
}

async fn download_config_files(
    conf_dir: String,
    frontend_url: String,
    node_name: String
) -> Result<()> {
    let files = list_config_files(frontend_url.clone()).await?;
    for f in files
        .into_iter()
        .filter(
            |f|
                f.filename.starts_with("assets_") ||
                f.filename.starts_with("intel_") ||
                f.filename.starts_with("vuln_") ||
                f.filename.starts_with(&format!("directives_{}", node_name.clone()))
        ) {
        let url = frontend_url.clone() + "/config/" + &f.filename;
        let resp = reqwest::get(url.clone()).await?;
        let content = resp.text().await?;
        let path = conf_dir.clone() + "/" + &f.filename;
        let mut local = File::create(path).context("cannot create config file")?;
        local.write_all(content.as_bytes()).context("cannot write file")?;
    }

    Ok(())
}