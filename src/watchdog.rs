use std::{ time::Duration, collections::HashMap };

use metered::{ metered, Throughput, hdr_histogram::HdrHistogram };
use tokio::{ sync::{ broadcast, mpsc }, time::interval };
use anyhow::Result;
use tracing::{ info, warn };

use crate::{ event::NormalizedEvent, manager::ManagerReport };

#[derive(Default)]
pub struct Watchdog {
    metrics: Metrics,
}

pub struct WatchdogOpt {
    pub event_tx: broadcast::Sender<NormalizedEvent>,
    pub event_rx: broadcast::Receiver<NormalizedEvent>,
    pub resptime_rx: mpsc::Receiver<Duration>,
    pub report_rx: mpsc::Receiver<ManagerReport>,
    pub cancel_tx: broadcast::Sender<()>,
    pub report_interval: u64,
    pub max_eps: u32,
}

#[metered(registry = Metrics)]
impl Watchdog {
    pub async fn start(&self, opt: WatchdogOpt) -> Result<()> {
        let mut report = interval(Duration::from_secs(opt.report_interval));
        let mut cancel_rx = opt.cancel_tx.subscribe();
        let mut resp_histo = HdrHistogram::with_bound(60 * 60 * 1000); // max 1 hour
        let max_proc_time_ms = round((Duration::from_secs(1) / opt.max_eps).as_millis() as f64, 3);
        let mut report_map: HashMap<u64, usize> = HashMap::new();
        let mut resptime_rx = opt.resptime_rx;
        let mut report_rx = opt.report_rx;
        let mut event_rx = opt.event_rx;

        loop {
            tokio::select! {
              _ = cancel_rx.recv() => {
                info!("cancel signal received, exiting watchdog thread");
                break;
              }
              Some(v) = resptime_rx.recv() => {
                if let Ok(n) = u64::try_from(v.as_millis()) {
                  resp_histo.record(n);
                }
              }
              Some(v) = report_rx.recv() => {
                report_map.insert(v.id, v.active_backlogs);
              }
              _ = report.tick() => {
                let eps = round(self.metrics.eps.throughput.histogram().mean(), 2);
                let avg_proc_time_ms = round(resp_histo.mean(), 3);
                let queue_length = opt.event_tx.len();
                let ttl_directives = report_map.len();
                let active_directives = report_map.iter().filter(|&(_, v)| *v > 0).count();
                let backlogs: usize = report_map.values().sum();
                info!(eps, queue_length, avg_proc_time_ms, ttl_directives, active_directives, backlogs, "watchdog report", );
                if queue_length != 0 && avg_proc_time_ms > max_proc_time_ms {
                  warn!(avg_proc_time_ms, "avg. processing time maybe too long to sustain the target {} event/sec (or {} ms/event)", opt.max_eps, max_proc_time_ms );
                }
              }
              Ok(_) = event_rx.recv() => {
                self.eps()
              }
            }
        }
        Ok(())
    }
    #[measure([Throughput])]
    fn eps(&self) {}
}

fn round(x: f64, decimals: u32) -> f64 {
    let y = (10i64).pow(decimals) as f64;
    (x * y).round() / y
}