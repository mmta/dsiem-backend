use clap::{ Parser, arg, command, Subcommand, Args };
use tracing::{ info, error };
use anyhow::{ Result, Error };
use tokio::sync::{ broadcast, mpsc, oneshot };

mod logger;
mod rule;
mod directive;
mod utils;
mod event;
mod asset;
mod worker;
mod manager;
mod backlog;

#[derive(Parser)]
#[command(
    author("https://github.com/mmta"),
    version,
    about = "Dsiem backend server",
    long_about = "Dsiem backend server\n\n\
    DSiem is an event correlation engine for ELK stack.\n\
    DSiem provides OSSIM-style correlation for normalized logs/events, and relies on\n\
    Filebeat, Logstash, and Elasticsearch to do the rest."
)]
struct Cli {
    #[command(subcommand)]
    subcommand: SubCommands,
    /// Increase logging verbosity
    #[arg(short('v'), long, action = clap::ArgAction::Count)]
    verbosity: u8,
}

#[derive(Subcommand)]
pub enum SubCommands {
    #[command(
        about = "Start Dsiem backend server",
        long_about = "Start the Dsiem backend server",
        name = "serve"
    )] ServeCommand(ServeArgs),
}

#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Frontend URL to pull configuration from
    #[arg(
        short('f'),
        long = "frontend",
        env = "DSIEM_FRONTEND",
        value_name = "url",
        default_value = "http://frontend:8080"
    )]
    pub frontend: String,
    /// Unique node name to use when deployed in cluster mode
    #[arg(short('n'), long = "node", env = "DSIEM_NODE", value_name = "string")]
    pub node: String,
    /// Min. alarm lifetime in minutes. Backlog won't expire sooner than this regardless rule timeouts. This is to support processing of delayed events
    #[arg(short('l'), long, env, value_name = "minutes", default_value_t = 0)]
    min_alarm_lifetime: u16,
    /// Alarm status to use, the first one will be assigned to new alarms
    #[arg(
        short('s'),
        long,
        env,
        value_name = "comma separated strings",
        use_value_delimiter = true,
        value_delimiter = ',',
        default_value = "Open, In-Progress, Closed"
    )]
    status: Vec<String>,
    /// Alarm tags to use, the first one will be assigned to new alarms
    #[arg(
        short('t'),
        long,
        env,
        value_name = "comma separated strings",
        use_value_delimiter = true,
        value_delimiter = ',',
        default_value = "Identified Threat, False Positive, Valid Threat, Security Incident"
    )]
    tags: Vec<String>,
    /// Minimum alarm risk value to be classified as Medium risk. Lower value than this will be classified as Low risk
    #[arg(long = "med_risk_min", value_name = "2 to 8", env, default_value_t = 3)]
    med_risk_min: u8,
    /// Maximum alarm risk value to be classified as Medium risk. Higher value than this will be classified as High risk
    #[arg(long = "med_risk_max", value_name = "2 to 9", env, default_value_t = 6)]
    med_risk_max: u8,
    /// Nats address to use for frontend - backend communication
    #[arg(
        long = "msq",
        env = "DSIEM_MSQ",
        value_name = "string",
        default_value = "nats://dsiem-nats:4222"
    )]
    msq: String,
    /// Cache expiration time in minutes for intel and vuln query results
    #[arg(short('c'), long = "cache", env, value_name = "minutes", default_value_t = 10)]
    cache_duration: u8,
    /// Length of queue for directive evaluation process, 0 means unlimited and will deactivate max_delay
    #[arg(short('q'), long = "max_queue", env, value_name = "events", default_value_t = 25000)]
    max_queue: usize,
    /// Duration in seconds before resetting overload condition state
    #[arg(long = "hold_duration", env, value_name = "seconds", default_value_t = 10)]
    hold_duration: u8,
    /// Check private IP addresses against threat intel
    #[arg(long = "intel_private_ip", env, default_value_t = false)]
    intel_private_ip: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    serve(true, true, false).await
}

fn log_startup_err(context: &str, err: Error) -> Error {
    error!("error {}: {}", context, err.to_string());
    err
}

async fn serve(listen: bool, require_logging: bool, test_env: bool) -> Result<()> {
    let args = Cli::parse();
    let level = logger::verbosity_to_level_filter(args.verbosity);
    let sub = logger::setup_logger(level)?;
    let log_result = tracing::subscriber::set_global_default(sub);

    if require_logging {
        log_result?;
    }

    if !listen {
        return Ok(());
    }

    let SubCommands::ServeCommand(sargs) = args.subcommand;
    info!("starting dsiem backend server using frontend at {}", sargs.frontend);

    let (event_tx, _) = broadcast::channel(sargs.max_queue);
    let (bp_tx, bp_rx) = mpsc::channel::<bool>(128);
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let event_tx_clone = event_tx.clone();

    let t = tokio::spawn(async {
        worker::start_worker(sargs.frontend, sargs.msq, sargs.node, event_tx, bp_rx, ready_tx).await
    });
    ready_rx.await?;
    let directives = directive
        ::load_directives(test_env)
        .map_err(|e| log_startup_err("loading directives", e))?;
    let assets = asset::NetworkAssets
        ::new(test_env)
        .map_err(|e| log_startup_err("loading assets", e))?;
    let manager = manager::Manager
        ::new(test_env, directives, assets, sargs.hold_duration, bp_tx, event_tx_clone)
        .map_err(|e| log_startup_err("loading manager", e))?;
    let t = tokio::spawn(async move { manager.listen().await });

    t.await?.map_err(|e| log_startup_err("starting worker", e))?;

    Ok(())
}