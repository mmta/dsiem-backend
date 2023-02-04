// ch chan<- event.NormalizedEvent, msq string, msqPrefix string, nodeName string, confDir string, frontend string

use std::{ fs::File, io::Write };
use futures::StreamExt;
use tokio::{ sync::{ broadcast::Sender, oneshot, mpsc::Receiver } };
use std::str;

use crate::{ utils, event::{ self, NormalizedEvent }, asset::NetworkAssets };
use serde::Deserialize;
use tracing::{ info, error, debug };
use anyhow::{ Result, Context, anyhow };

#[derive(Deserialize)]
struct ConfigFile {
    filename: String,
}
#[derive(Deserialize)]
struct ConfigFiles {
    files: Vec<ConfigFile>,
}

pub async fn start_worker(
    frontend_url: String,
    nats_url: String,
    node_name: String,
    event_tx: Sender<event::NormalizedEvent>,
    bp_rx: Receiver<bool>,
    ready_tx: oneshot::Sender<()>,
    assets: &NetworkAssets
) -> Result<()> {
    let config_dir = utils::config_dir(false)?;
    download_config_files(config_dir.to_string_lossy().to_string(), frontend_url, node_name).await?;
    ready_tx.send(()).map_err(|_| anyhow!("cannot send ready signal"))?;

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
        .connect(nats_url.clone()).await
        .context(format!("cannot connect to nats {}", nats_url))?;

    let mut subscription = client
        .subscribe("dsiem_events".into()).await
        .map_err(|e| anyhow!("{}", e))
        .context(format!("cannot subscribe to dsiem_events from {}", nats_url))?;

    info!("worker listening for new events");
    while let Some(message) = subscription.next().await {
        if let Ok(v) = str::from_utf8(&message.payload) {
            let res: Result<NormalizedEvent, serde_json::Error> = serde_json::from_str(v);
            if res.is_err() {
                error!(
                    "cannot parse event from message queue: {:?}, skipping it",
                    res.unwrap_err()
                );
                continue;
            }
            let e = res.unwrap();
            if assets.is_whitelisted(&e.src_ip) {
                continue;
            }
            let res = event_tx.send(e.clone());
            if res.is_err() {
                error!("cannot send event {}: {}, skipping it", e.id, res.unwrap_err());
            } else {
                debug!("event {} broadcasted", e.id);
            }
        } else {
            error!("an event contain bytes that cant be parsed, skipping it");
        }
    }

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
        local.write_all(content.as_bytes()).context("cannot create write file")?;
    }

    Ok(())
}