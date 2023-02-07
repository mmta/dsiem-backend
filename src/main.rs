use std::sync::Arc;

use std::time::Duration;
use clap::{ Parser, arg, command, Subcommand, Args };
use tokio::{ task, time::timeout };
use tracing::{ info, error, debug };
use anyhow::{ Result, Error, anyhow };
use tokio::sync::{ broadcast, mpsc, oneshot };
use crate::{ manager::ManagerOpt };

mod logger;
mod rule;
mod directive;
mod utils;
mod event;
mod asset;
mod worker;
mod manager;
mod backlog;
mod intel;
mod watchdog;

#[derive(Parser)]
#[command(
    author("https://github.com/mmta"),
    version,
    about = "Dsiem backend server",
    long_about = "Dsiem backend server\n\n\
    Dsiem is an event correlation engine for ELK stack.\n\
    Dsiem provides OSSIM-style correlation for normalized logs/events, and relies on\n\
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
    // Maximum expected rate of events/second
    #[arg(short('e'), long = "max_eps", value_name = "number", env, default_value_t = 1000)]
    max_eps: u32,
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
    /// Length of queue for unprocessed events, set this to a high number to emulate unbounded queue
    #[arg(short('q'), long = "max_queue", env, value_name = "events", default_value_t = 25000)]
    max_queue: usize,
    /// Duration in seconds before resetting overload condition state
    #[arg(long = "hold_duration", env, value_name = "seconds", default_value_t = 10)]
    hold_duration: u8,
    /// Max. processing delay before throttling incoming events (under-pressure condition), 0 means disabled"
    #[arg(short = 'd', long = "max_delay", env, value_name = "seconds", default_value_t = 180)]
    max_delay: u16,
    /// Check private IP addresses against threat intel
    #[arg(long = "intel_private_ip", env, default_value_t = false)]
    intel_private_ip: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    serve(true, true, false).await
}

fn log_startup_err(context: &str, err: Error) -> Error {
    error!("error {}: {:?}", context, err);
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

    // we take in unsigned values from CLI to make sure there's no negative numbers, and convert them
    // to signed value required by timestamp related APIs.
    let max_delay = chrono::Duration
        ::seconds(sargs.max_delay.into())
        .num_nanoseconds()
        .ok_or_else(|| log_startup_err("reading max_delay", anyhow!("invalid value provided")))?;
    let min_alarm_lifetime = chrono::Duration
        ::minutes(sargs.min_alarm_lifetime.into())
        .num_seconds();
    if sargs.med_risk_min < 2 || sargs.med_risk_max > 9 || sargs.med_risk_min == sargs.med_risk_max {
        return Err(
            log_startup_err(
                "reading med_risk_min and med_risk_max",
                anyhow!("invalid value provided")
            )
        );
    }

    let (event_tx, event_rx) = broadcast::channel(sargs.max_queue);
    let (bp_tx, bp_rx) = mpsc::channel::<()>(8);
    let (resptime_tx, resptime_rx) = mpsc::channel::<Duration>(128);
    let (cancel_tx, cancel_rx) = broadcast::channel::<()>(1);
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let event_tx_clone = event_tx.clone();

    let assets = Arc::new(
        asset::NetworkAssets::new(test_env).map_err(|e| log_startup_err("loading assets", e))?
    );

    let worker_handle = task::spawn({
        let assets = assets.clone();
        let event_tx = event_tx.clone();
        async move {
            let opt = worker::WorkerOpt {
                event_tx,
                bp_rx,
                ready_tx,
                cancel_rx,
                assets,
                frontend_url: sargs.frontend,
                nats_url: sargs.msq,
                node_name: sargs.node,
                hold_duration: sargs.hold_duration,
            };
            let w = worker::Worker {};
            w.start(opt).await.map_err(|e| {
                error!("worker error: {:?}", e);
                e
            })
        }
    });
    timeout(std::time::Duration::from_secs(5), ready_rx).await.map_err(|_|
        log_startup_err(
            "waiting for worker",
            anyhow!("5 seconds timeout occurred, likely wrong frontend or msq URLs")
        )
    )??;

    let directives = directive
        ::load_directives(test_env)
        .map_err(|e| log_startup_err("loading directives", e))?;

    let intels = Arc::new(
        intel::load_intel(test_env).map_err(|e| log_startup_err("loading intels", e))?
    );

    let opt = ManagerOpt {
        test_env,
        directives,
        assets,
        intels,
        max_delay,
        min_alarm_lifetime,
        backpressure_tx: bp_tx,
        resptime_tx,
        cancel_tx: cancel_tx.clone(),
        publisher: event_tx_clone,
        med_risk_max: sargs.med_risk_max,
        med_risk_min: sargs.med_risk_min,
        default_status: sargs.status[0].clone(),
        default_tag: sargs.tags[0].clone(),
        intel_private_ip: sargs.intel_private_ip,
    };
    let manager = manager::Manager::new(opt).map_err(|e| log_startup_err("loading manager", e))?;
    let manager_handle = task::spawn(async { manager.listen().await.map_err(|e| {
            error!("{:?}", e);
            e
        }) });

    let watchdog_handle = task::spawn(async move {
        let w = watchdog::Watchdog::default();
        w.start(event_tx, event_rx, resptime_rx, cancel_tx, sargs.max_eps).await.map_err(|e| {
            error!("{:?}", e);
            e
        })
    });
    let (worker_res, manager_res, watchdog_res) = tokio::join!(
        worker_handle,
        manager_handle,
        watchdog_handle
    );
    debug!("about to get result");
    worker_res??;
    manager_res??;
    watchdog_res??;
    Ok(())
}