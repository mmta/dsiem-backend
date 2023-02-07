use std::time::Duration;

use metered::{ metered, Throughput, hdr_histogram::HdrHistogram };
use tokio::{ sync::{ broadcast, mpsc }, time::interval };
use anyhow::Result;
use tracing::{ info, warn };

use crate::event::NormalizedEvent;

const REPORT_INTERVAL: u64 = 10;

#[derive(Default)]
pub struct Watchdog {
    metrics: Metrics,
}

#[metered(registry = Metrics)]
impl Watchdog {
    pub async fn start(
        &self,
        event_tx: broadcast::Sender<NormalizedEvent>,
        mut event_rx: broadcast::Receiver<NormalizedEvent>,
        mut resptime_rx: mpsc::Receiver<Duration>,
        cancel_tx: broadcast::Sender<()>,
        max_eps: u32
    ) -> Result<()> {
        let mut report = interval(Duration::from_secs(REPORT_INTERVAL));
        let mut cancel_rx = cancel_tx.subscribe();
        let mut resp_histo = HdrHistogram::with_bound(60 * 60 * 1000); // max 1 hour
        let max_proc_time_ms = round((Duration::from_secs(1) / max_eps).as_millis() as f64, 3);

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
            
              _ = report.tick() => {
                let eps = round(self.metrics.eps.throughput.histogram().mean(), 2);
                let avg_processing_time_ms = round(resp_histo.mean(), 3);
                let queue_length = event_tx.len();
                info!(eps, queue_length, avg_processing_time_ms, max_proc_time_ms, "watchdog tick report", );
                if queue_length != 0 && avg_processing_time_ms > max_proc_time_ms {
                  warn!(avg_processing_time_ms, "avg. processing time maybe too long to sustain the target {} event/sec (or {} ms/event)", max_eps, max_proc_time_ms );
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