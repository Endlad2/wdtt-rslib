// SPDX-License-Identifier: LGPL-2.1
//
//! Machine-readable events for the host application.
//!
//! The format is byte-compatible with the reference WDTT client so existing
//! parsers (Android `TunnelEventParser`, LaLune) keep working:
//!
//! ```text
//! __WDTT_EVENT__|READY|
//! __WDTT_EVENT__|CONFIG|{"config":"[Interface]\n..."}
//! __WDTT_EVENT__|STATS|{"active":12,"bytes_up":123,"bytes_down":456}
//! ```
//!
//! Events are only printed when `WDTT_EVENTS=1`, exactly like the original.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use serde_json::json;

use crate::stats::Stats;

const EVENT_PREFIX: &str = "__WDTT_EVENT__|";

static ENABLED: OnceLock<AtomicBool> = OnceLock::new();

fn enabled() -> &'static AtomicBool {
    ENABLED.get_or_init(|| AtomicBool::new(std::env::var("WDTT_EVENTS").as_deref() == Ok("1")))
}

/// Forces event output on or off, regardless of `WDTT_EVENTS`.
///
/// Used by `--events` so the host can opt in without setting an environment
/// variable (useful on Android and iOS).
pub fn set_enabled(value: bool) {
    enabled().store(value, Ordering::Relaxed);
}

pub fn is_enabled() -> bool {
    enabled().load(Ordering::Relaxed)
}

/// Event kinds, identical to the reference implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Started,
    Stopped,
    Ready,
    Config,
    Stats,
    Error,
    CaptchaRequest,
    CaptchaDone,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Started => "STARTED",
            EventKind::Stopped => "STOPPED",
            EventKind::Ready => "READY",
            EventKind::Config => "CONFIG",
            EventKind::Stats => "STATS",
            EventKind::Error => "ERROR",
            EventKind::CaptchaRequest => "CAPTCHA_REQUEST",
            EventKind::CaptchaDone => "CAPTCHA_DONE",
        }
    }
}

/// Emits an event with an optional JSON payload.
pub fn emit(kind: EventKind, payload: Option<serde_json::Value>) {
    if !is_enabled() {
        return;
    }
    let body = payload.map(|p| p.to_string()).unwrap_or_default();
    println!("{EVENT_PREFIX}{}|{}", kind.as_str(), body);
}

/// Emits a non-fatal or fatal error event.
pub fn emit_error(code: &str, message: &str, fatal: bool) {
    emit(
        EventKind::Error,
        Some(json!({ "code": code, "message": message, "fatal": fatal })),
    );
}

/// Emits a traffic/worker snapshot.
pub fn emit_stats(stats: &Stats) {
    emit(
        EventKind::Stats,
        Some(json!({
            "active": stats.active(),
            "bytes_up": stats.bytes_up(),
            "bytes_down": stats.bytes_down(),
        })),
    );
}

/// Signals that the tunnel can carry traffic.
///
/// Emitted at most once per process: every worker reaches readiness on its own,
/// but the host application only needs the first confirmation.
pub fn emit_ready() {
    static ANNOUNCED: std::sync::Once = std::sync::Once::new();
    ANNOUNCED.call_once(|| emit(EventKind::Ready, None));
}

/// Delivers the WireGuard config handed out by the server.
pub fn emit_config(config: &str) {
    emit(EventKind::Config, Some(json!({ "config": config })));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_names_match_the_reference_protocol() {
        assert_eq!(EventKind::Started.as_str(), "STARTED");
        assert_eq!(EventKind::Stopped.as_str(), "STOPPED");
        assert_eq!(EventKind::Ready.as_str(), "READY");
        assert_eq!(EventKind::Config.as_str(), "CONFIG");
        assert_eq!(EventKind::Stats.as_str(), "STATS");
        assert_eq!(EventKind::Error.as_str(), "ERROR");
        assert_eq!(EventKind::CaptchaRequest.as_str(), "CAPTCHA_REQUEST");
        assert_eq!(EventKind::CaptchaDone.as_str(), "CAPTCHA_DONE");
    }

    #[test]
    fn toggling_enabled_is_observable() {
        let before = is_enabled();
        set_enabled(true);
        assert!(is_enabled());
        set_enabled(false);
        assert!(!is_enabled());
        set_enabled(before);
    }
}
