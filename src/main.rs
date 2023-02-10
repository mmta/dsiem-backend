use std::sync::Arc;

use std::time::Duration;
use clap::{ Parser, arg, command, Subcommand, Args };
use tokio::{ task, time::timeout };
use tracing::{ info, error };
use anyhow::{ Result, Error, anyhow };
use tokio::sync::{ broadcast, mpsc, oneshot };
use crate::{ manager::ManagerOpt, watchdog::WatchdogOpt, asset::NetworkAssets };

mod asset;
mod event;
mod rule;
mod directive;
mod backlog;
mod worker;
mod manager;
mod watchdog;
mod intel;
mod logger;
mod utils;
mod config;

const REPORT_INTERVAL_IN_SECONDS: u64 = 10;

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
    /// Enable debug output, for compatibility purpose
    #[arg(long = "debug", env = "DSIEM_DEBUG", value_name = "boolean", default_value_t = false)]
    pub debug: bool,
    /// Enable trace output, for compatibility purpose
    #[arg(long = "trace", env = "DSIEM_TRACE", value_name = "boolean", default_value_t = false)]
    pub trace: bool,
    /// Enable json-lines log output
    #[arg(
        short('j'),
        long = "json",
        env = "DSIEM_JSON",
        value_name = "boolean",
        default_value_t = false
    )]
    pub use_json: bool,
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
    #[arg(
        short('l'),
        long,
        env = "DSIEM_MINALARMLIFETIME",
        value_name = "minutes",
        default_value_t = 0
    )]
    min_alarm_lifetime: u16,
    /// Alarm status to use, the first one will be assigned to new alarms
    #[arg(
        short('s'),
        long,
        env = "DSIEM_STATUS",
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
        env = "DSIEM_TAGS",
        value_name = "comma separated strings",
        use_value_delimiter = true,
        value_delimiter = ',',
        default_value = "Identified Threat, False Positive, Valid Threat, Security Incident"
    )]
    tags: Vec<String>,
    /// Minimum alarm risk value to be classified as Medium risk. Lower value than this will be classified as Low risk
    #[arg(
        long = "med_risk_min",
        value_name = "2 to 8",
        env = "DSIEM_MEDRISKMIN",
        default_value_t = 3
    )]
    med_risk_min: u8,
    /// Maximum alarm risk value to be classified as Medium risk. Higher value than this will be classified as High risk
    #[arg(
        long = "med_risk_max",
        value_name = "2 to 9",
        env = "DSIEM_MEDRISKMAX",
        default_value_t = 6
    )]
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
    #[arg(
        short('c'),
        long = "cache",
        env = "DSIEM_CACHEDURATION",
        value_name = "minutes",
        default_value_t = 10
    )]
    cache_duration: u8,
    /// Length of queue for unprocessed events, setting this to 0 will use 1,000,000 events to emulate unbounded queue
    #[arg(
        short('q'),
        long = "max_queue",
        env = "DSIEM_MAXQUEUE",
        value_name = "events",
        default_value_t = 25000
    )]
    max_queue: usize,
    /// Duration in seconds before resetting overload condition state
    #[arg(
        long = "hold_duration",
        env = "DSIEM_HOLDDURATION",
        value_name = "seconds",
        default_value_t = 10
    )]
    hold_duration: u8,
    /// Max. processing delay before throttling incoming events (under-pressure condition), 0 means disabled"
    #[arg(
        short = 'd',
        long = "max_delay",
        env = "DSIEM_MAXDELAY",
        value_name = "seconds",
        default_value_t = 180
    )]
    max_delay: u16,
    /// Check private IP addresses against threat intel
    #[arg(long = "intel_private_ip", env = "DSIEM_INTELPRIVATEIP", default_value_t = false)]
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
    let verbosity = if args.debug { 1 } else if args.trace { 2 } else { args.verbosity };
    let level = logger::verbosity_to_level_filter(verbosity);
    let sub_json = logger::setup_logger_json(level)?;
    let sub = logger::setup_logger(level)?;
    let log_result = if args.use_json {
        tracing::subscriber::set_global_default(sub_json)
    } else {
        tracing::subscriber::set_global_default(sub)
    };
    if require_logging {
        log_result?;
    }

    if !listen {
        return Ok(());
    }

    let SubCommands::ServeCommand(sargs) = args.subcommand;
    info!(
        "starting dsiem backend server with frontend {} and message queue {}",
        sargs.frontend,
        sargs.msq
    );

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
    let max_queue = if sargs.max_queue == 0 { 1_000_000 } else { sargs.max_queue };

    let (event_tx, event_rx) = broadcast::channel(max_queue);
    let (bp_tx, bp_rx) = mpsc::channel::<()>(8);
    let (resptime_tx, resptime_rx) = mpsc::channel::<Duration>(128);
    let (cancel_tx, cancel_rx) = broadcast::channel::<()>(1);
    let (ready_tx, ready_rx) = oneshot::channel::<()>();
    let event_tx_clone = event_tx.clone();

    let c = cancel_tx.clone();
    ctrlc::set_handler(move || {
        let _ = c.send(());
    })?;

    config
        ::download_files(test_env, sargs.frontend, sargs.node).await
        .map_err(|e| log_startup_err("downloading config", e))?;

    let assets = Arc::new(
        NetworkAssets::new(test_env).map_err(|e| log_startup_err("loading assets", e))?
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
                nats_url: sargs.msq,
                hold_duration: sargs.hold_duration,
            };
            let w = worker::Worker {};
            w.start(opt).await.map_err(|e| {
                error!("worker error: {:?}", e);
                e
            })
        }
    });
    timeout(std::time::Duration::from_secs(10), ready_rx).await.map_err(|_|
        log_startup_err(
            "waiting for worker",
            anyhow!("10 seconds timeout occurred, likely wrong msq URLs")
        )
    )??;

    let directives = directive
        ::load_directives(test_env, None)
        .map_err(|e| log_startup_err("loading directives", e))?;

    let intels = Arc::new(
        intel::load_intel(test_env).map_err(|e| log_startup_err("loading intels", e))?
    );

    let (report_tx, report_rx) = mpsc::channel::<manager::ManagerReport>(directives.len());

    let watchdog_handle = task::spawn({
        let cancel_tx = cancel_tx.clone();
        let opt = WatchdogOpt {
            event_tx,
            event_rx,
            resptime_rx,
            report_rx,
            cancel_tx,
            report_interval: REPORT_INTERVAL_IN_SECONDS,
            max_eps: sargs.max_eps,
        };
        async move {
            let w = watchdog::Watchdog::default();
            w.start(opt).await.map_err(|e| {
                error!("{:?}", e);
                e
            })
        }
    });

    let opt = ManagerOpt {
        test_env,
        directives,
        assets,
        intels,
        max_delay,
        min_alarm_lifetime,
        backpressure_tx: bp_tx,
        resptime_tx,
        cancel_tx,
        publisher: event_tx_clone,
        med_risk_max: sargs.med_risk_max,
        med_risk_min: sargs.med_risk_min,
        default_status: sargs.status[0].clone(),
        default_tag: sargs.tags[0].clone(),
        intel_private_ip: sargs.intel_private_ip,
        report_tx,
    };
    let manager = manager::Manager::new(opt).map_err(|e| log_startup_err("loading manager", e))?;
    let manager_handle = task::spawn(async { manager
            .listen(REPORT_INTERVAL_IN_SECONDS).await
            .map_err(|e| {
                error!("{:?}", e);
                e
            }) });

    let (worker_res, manager_res, watchdog_res) = tokio::join!(
        worker_handle,
        manager_handle,
        watchdog_handle
    );
    worker_res??;
    manager_res??;
    watchdog_res??;
    Ok(())
}