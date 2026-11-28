// SPDX-License-Identifier: LGPL-2.1
//
//! Tunnel counters shared between workers and the status loop.

// MIPS32 и другие 32-битные цели без 64-битных атомиков: portable-atomic
// подставляет корректную реализацию (на остальных платформах это те же
// std-атомики без накладных расходов).
use portable_atomic::{AtomicI64, AtomicU64};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Counters for one client process.
#[derive(Debug, Default)]
pub struct Stats {
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    active: AtomicU32,
    workers: AtomicU32,
    workers_target: AtomicU32,
    /// Bytes per second, refreshed by the status loop.
    rate_up: AtomicU64,
    rate_down: AtomicU64,
    /// Milliseconds since the tunnel became ready.
    connected_since: AtomicI64,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn add_up(&self, bytes: u64) {
        self.bytes_up.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_down(&self, bytes: u64) {
        self.bytes_down.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn bytes_up(&self) -> u64 {
        self.bytes_up.load(Ordering::Relaxed)
    }

    pub fn bytes_down(&self) -> u64 {
        self.bytes_down.load(Ordering::Relaxed)
    }

    pub fn worker_started(&self) {
        self.active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn worker_stopped(&self) {
        // Saturating: a stop without a matching start must not underflow.
        // `fetch_update` is the MSRV-compatible spelling of `try_update`.
        #[allow(deprecated)]
        let _ = self
            .active
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    pub fn active(&self) -> u32 {
        self.active.load(Ordering::Relaxed)
    }

    pub fn set_workers(&self, current: u32, target: u32) {
        self.workers.store(current, Ordering::Relaxed);
        self.workers_target.store(target, Ordering::Relaxed);
    }

    pub fn workers(&self) -> (u32, u32) {
        (
            self.workers.load(Ordering::Relaxed),
            self.workers_target.load(Ordering::Relaxed),
        )
    }

    pub fn set_rates(&self, up: u64, down: u64) {
        self.rate_up.store(up, Ordering::Relaxed);
        self.rate_down.store(down, Ordering::Relaxed);
    }

    pub fn rates(&self) -> (u64, u64) {
        (
            self.rate_up.load(Ordering::Relaxed),
            self.rate_down.load(Ordering::Relaxed),
        )
    }

    pub fn mark_connected(&self, epoch_millis: i64) {
        self.connected_since.store(epoch_millis, Ordering::Relaxed);
    }

    pub fn connected_since(&self) -> i64 {
        self.connected_since.load(Ordering::Relaxed)
    }

    /// Total traffic in bytes.
    pub fn total(&self) -> u64 {
        self.bytes_up() + self.bytes_down()
    }
}

/// Formats a byte count the way the reference client logs it (`12.34 МБ`).
pub fn format_mb(bytes: u64) -> String {
    format!("{:.2} МБ", bytes as f64 / (1024.0 * 1024.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        let s = Stats::new();
        s.add_up(100);
        s.add_down(250);
        assert_eq!(s.bytes_up(), 100);
        assert_eq!(s.bytes_down(), 250);
        assert_eq!(s.total(), 350);
    }

    #[test]
    fn active_never_underflows() {
        let s = Stats::new();
        s.worker_stopped();
        assert_eq!(s.active(), 0);
        s.worker_started();
        s.worker_started();
        assert_eq!(s.active(), 2);
        s.worker_stopped();
        assert_eq!(s.active(), 1);
    }

    #[test]
    fn workers_and_rates_round_trip() {
        let s = Stats::new();
        s.set_workers(5, 9);
        assert_eq!(s.workers(), (5, 9));
        s.set_rates(1000, 2000);
        assert_eq!(s.rates(), (1000, 2000));
    }

    #[test]
    fn formats_megabytes() {
        assert_eq!(format_mb(0), "0.00 МБ");
        assert_eq!(format_mb(1024 * 1024), "1.00 МБ");
    }
}
