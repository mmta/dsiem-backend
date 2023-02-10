use std::{ fs::File, io::Write };
use std::str;

use crate::utils;
use serde::Deserialize;
use tracing::debug;
use anyhow::{ Result, Context };

#[derive(Deserialize)]
struct ConfigFile {
    filename: String,
}
#[derive(Deserialize)]
struct ConfigFiles {
    files: Vec<ConfigFile>,
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

pub async fn download_files(test_env: bool, frontend_url: String, node_name: String) -> Result<()> {
    let config_dir = utils::config_dir(test_env, None)?.to_string_lossy().to_string();
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
        let path = config_dir.clone() + "/" + &f.filename;
        let mut local = File::create(&path).context(format!("cannot create config file {}", path))?;
        local.write_all(content.as_bytes()).context("cannot write file")?;
    }

    Ok(())
}