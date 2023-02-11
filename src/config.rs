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

pub async fn download_files(
    test_env: bool,
    subdir: Option<Vec<String>>,
    frontend_url: String,
    node_name: String
) -> Result<()> {
    let config_dir = utils::config_dir(test_env, subdir)?.to_string_lossy().to_string();
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

#[cfg(test)]
mod test {
    use tracing_test::traced_test;

    use super::*;
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    #[traced_test]
    async fn test_config() {
        let mut server = mockito::Server::new_async().await;
        let url = server.url();
        debug!("using url: {}", url.clone());
        tokio::spawn(async move {
            let _m1 = server.mock("GET", "/config/").with_status(418).create_async().await;
        });

        let res = list_config_files(url).await;
        assert!(res.is_err());

        let file_list =
            r#"{ 
                "files" : [
                  {"filename" : "assets_foo.json"},
                  {"filename" : "intel_bar.json"},
                  {"filename" : "vuln_baz.json"}
                ] 
            }"#;

        let mut server = mockito::Server::new_async().await;
        let url = server.url();
        debug!("using url: {}", url.clone());
        tokio::spawn(async move {
            let _m1 = server
                .mock("GET", "/config/")
                .with_status(200)
                .with_body(file_list)
                .create_async().await;
            let _m2 = server
                .mock("GET", "/config/assets_foo.json")
                .with_status(200)
                .with_body("{}")
                .create_async().await;
            let _m3 = server
                .mock("GET", "/config/intel_bar.json")
                .with_status(200)
                .with_body("{}")
                .create_async().await;
            let _m4 = server
                .mock("GET", "/config/vuln_baz.json")
                .with_status(200)
                .with_body("{}")
                .create_async().await;
        });

        let config_files = list_config_files(url.clone()).await.unwrap();
        assert!(config_files.len() == 3);
        assert!(logs_contain("listing config files from"));
        let res = download_files(
            true,
            Some(vec!["dl_config".to_owned()]),
            url,
            "qux".to_owned()
        ).await;
        assert!(res.is_ok());
    }
}