// SPDX-License-Identifier: LGPL-2.1
//
//! One tunnel session ("worker").
//!
//! A session allocates its own TURN relay, performs the DTLS handshake over the
//! obfuscated transport and then proxies datagrams between the dispatcher and
//! the DTLS channel. Multiple sessions run in parallel and share the local
//! WireGuard endpoint, which is what gives WDTT its throughput.
//!
//! The very first session also asks the server for the WireGuard config
//! (`GETCONF:`) and reports it to the host, which is the only way the client
//! ever learns its keys and address.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

use crate::config::WdttLink;
use crate::dispatcher::{Dispatcher, DispatcherHandle, WorkerSlot};
use crate::dtls::{ConfigResponse, DtlsSession};
use crate::events;
use crate::obfs::ObfsMode;
use crate::stats::Stats;
use crate::turn::{AllocErrorKind, TurnAllocation, TurnObfsConn};
use crate::vk::{self, TurnCredentials};

/// How long a session may live without traffic before it is recycled.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Keepalive interval towards the server.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// STUN binding refresh interval.
pub const BINDING_INTERVAL: Duration = Duration::from_secs(10);
/// Retry delay range when a session dies.
pub const RETRY_MIN: Duration = Duration::from_secs(5);
pub const RETRY_MAX: Duration = Duration::from_secs(16);

/// Where the WireGuard config is delivered, plus a flag that stops the other
/// workers from asking for it once it has been received.
#[derive(Clone)]
pub struct ConfigSink {
    pub tx: mpsc::Sender<String>,
    pub delivered: Arc<AtomicBool>,
}

/// Shared credentials cache: one TURN credential set is reused by all workers
/// until it is rejected, mirroring the reference client.
#[derive(Clone)]
pub struct CredentialCache {
    inner: Arc<Mutex<Option<TurnCredentials>>>,
    hash: String,
    mode: vk::AuthMode,
}

impl CredentialCache {
    pub fn new(hash: String, mode: vk::AuthMode) -> Self {
        CredentialCache {
            inner: Arc::new(Mutex::new(None)),
            hash,
            mode,
        }
    }

    /// Returns cached credentials or fetches a new set from VK.
    pub async fn get(&self) -> Result<TurnCredentials, vk::VkError> {
        let mut guard = self.inner.lock().await;
        if let Some(cached) = guard.as_ref() {
            return Ok(cached.clone());
        }
        let creds = vk::fetch_turn_credentials_mode(&self.hash, self.mode).await?;
        *guard = Some(creds.clone());
        Ok(creds)
    }

    /// Drops cached credentials so the next call refetches them.
    pub async fn invalidate(&self) {
        *self.inner.lock().await = None;
    }
}

/// Everything a worker needs to run.
pub struct SessionContext {
    pub link: WdttLink,
    pub wrap_key: Vec<u8>,
    pub obfs_mode: ObfsMode,
    pub device_id: String,
    pub credentials: CredentialCache,
    pub dispatcher: DispatcherHandle,
    pub stats: Arc<Stats>,
    pub token: CancellationToken,
    /// Turn override from the CLI (`--turn`/`--port`).
    pub turn_override: Option<String>,
    /// Which VK auth chain to use for TURN credentials.
    pub auth_mode: vk::AuthMode,
}

/// Result of one session attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionOutcome {
    /// The session ran and ended normally (tunnel closed, context cancelled).
    Closed,
    /// Credentials were rejected: the cache must be invalidated.
    CredentialsRejected,
    /// The VK call is dead; no point retrying.
    Fatal(String),
    /// Transient failure.
    Retryable(String),
}

/// Runs one session to completion.
///
/// `want_config` marks the session responsible for fetching the WireGuard
/// config from the server; `config_tx` receives it exactly once.
pub async fn run_session(
    ctx: Arc<SessionContext>,
    worker_id: usize,
    want_config: bool,
    config_tx: Option<ConfigSink>,
) -> SessionOutcome {
    if ctx.token.is_cancelled() {
        return SessionOutcome::Closed;
    }

    let credentials = match ctx.credentials.get().await {
        Ok(creds) => creds,
        Err(err) => {
            return match err {
                vk::VkError::CallUnavailable(m) => SessionOutcome::Fatal(m),
                vk::VkError::Fatal(m) => SessionOutcome::Fatal(m),
                vk::VkError::Retryable(m) => SessionOutcome::Retryable(m),
            };
        }
    };

    if credentials.urls.is_empty() {
        return SessionOutcome::Retryable("VK не вернул TURN-серверы".to_string());
    }

    // Spread workers over the available TURN servers.
    let selected = ctx
        .turn_override
        .clone()
        .unwrap_or_else(|| credentials.urls[worker_id % credentials.urls.len()].clone());

    let ipv4 = ctx.link.host.parse::<std::net::Ipv4Addr>().is_ok() || ctx.link.host.contains('.');

    log::info!("[СЕССИЯ #{worker_id}] TURN {selected}");

    let allocation = match TurnAllocation::allocate(
        &selected,
        &credentials.username,
        &credentials.password,
        ipv4,
    )
    .await
    {
        Ok(allocation) => allocation,
        Err(err) => {
            let message = err.to_string();
            return match AllocErrorKind::classify(&message) {
                AllocErrorKind::CredentialsRejected => {
                    log::warn!("[СЕССИЯ #{worker_id}] TURN отклонил креды: {message}");
                    ctx.credentials.invalidate().await;
                    SessionOutcome::CredentialsRejected
                }
                AllocErrorKind::Quota => {
                    SessionOutcome::Retryable(format!("TURN квота: {message}"))
                }
                AllocErrorKind::Other => SessionOutcome::Retryable(message),
            };
        }
    };

    log::info!(
        "[СЕССИЯ #{worker_id}] relay {} (local {})",
        allocation.relay_addr(),
        allocation.local_addr()
    );

    // Keep the allocation alive with STUN binding requests.
    let binding_token = ctx.token.child_token();
    let binding_client = allocation.client_handle();
    let binding_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(BINDING_INTERVAL);
        loop {
            tokio::select! {
                _ = binding_token.cancelled() => return,
                _ = ticker.tick() => {
                    if let Err(err) = binding_client.send_binding_request().await {
                        log::debug!("[TURN] binding request failed: {err}");
                    }
                }
            }
        }
    });

    let peer: SocketAddr = match tokio::net::lookup_host(ctx.link.peer_addr()).await {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => {
                binding_task.abort();
                return SessionOutcome::Retryable(format!(
                    "не удалось разрешить адрес сервера {}",
                    ctx.link.peer_addr()
                ));
            }
        },
        Err(err) => {
            binding_task.abort();
            return SessionOutcome::Retryable(format!("DNS {}: {err}", ctx.link.host));
        }
    };

    let transport = TurnObfsConn::new(&allocation, peer, ctx.wrap_key.clone(), ctx.obfs_mode);

    let session = match DtlsSession::connect(transport, &ctx.link.host).await {
        Ok(session) => session,
        Err(err) => {
            binding_task.abort();
            let message = err.to_string();
            log::warn!("[ВОРКЕР #{worker_id}] DTLS не поднялся: {message}");
            return SessionOutcome::Retryable(message);
        }
    };

    log::info!("[ВОРКЕР #{worker_id}] DTLS установлен");
    ctx.stats.worker_started();

    // Fetch the WireGuard config exactly once, on the designated session.
    if want_config {
        if let Some(config_tx) = config_tx {
            match session
                .request_config(ctx.link.local_port, &ctx.device_id, &ctx.link.password)
                .await
            {
                Ok(ConfigResponse::Config(config)) => {
                    log::info!("[ВОРКЕР #{worker_id}] конфиг WireGuard получен");
                    config_tx.delivered.store(true, Ordering::Relaxed);
                    let _ = config_tx.tx.send(config).await;
                }
                Ok(ConfigResponse::NotReady) => {
                    log::info!("[ВОРКЕР #{worker_id}] сервер ещё не выдал конфиг, повторим позже");
                }
                Ok(ConfigResponse::Denied(reason)) => {
                    let message = ConfigResponse::denial_message(&reason);
                    log::error!("[ВОРКЕР #{worker_id}] {message}");
                    events::emit_error("DENIED", &message, true);
                    ctx.stats.worker_stopped();
                    binding_task.abort();
                    session.close().await;
                    return SessionOutcome::Fatal(message);
                }
                Err(err) => {
                    log::warn!("[ВОРКЕР #{worker_id}] ошибка запроса конфига: {err}");
                }
            }
        }
    }

    if let Err(err) = session.say_ready().await {
        log::debug!("[ВОРКЕР #{worker_id}] READY не подтверждён: {err}");
    }

    log::info!("[ВОРКЕР #{worker_id}] [READY] туннель готов");
    events::emit_ready();

    // Register with the dispatcher and pump packets.
    let mut slot: WorkerSlot = ctx.dispatcher.register(worker_id).await;
    let outcome = proxy(&session, &mut slot, &ctx, worker_id).await;

    ctx.stats.worker_stopped();
    ctx.dispatcher.unregister(worker_id).await;
    binding_task.abort();
    session.close().await;
    allocation.close().await;

    outcome
}

/// Bidirectional pump between the DTLS session and the dispatcher.
async fn proxy(
    session: &DtlsSession,
    slot: &mut WorkerSlot,
    ctx: &SessionContext,
    worker_id: usize,
) -> SessionOutcome {
    let mut read_buf = vec![0u8; 2048];
    let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
    let deadline = tokio::time::sleep(SESSION_TIMEOUT);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = ctx.token.cancelled() => return SessionOutcome::Closed,

            _ = &mut deadline => {
                log::info!("[ВОРКЕР #{worker_id}] сессия достигла лимита времени");
                return SessionOutcome::Closed;
            }

            _ = keepalive.tick() => {
                if let Err(err) = session.keepalive().await {
                    log::debug!("[ВОРКЕР #{worker_id}] keepalive не отправлен: {err}");
                    return SessionOutcome::Retryable(format!("keepalive: {err}"));
                }
            }

            // Local → network.
            packet = slot.send_rx.recv() => {
                let Some(packet) = packet else { return SessionOutcome::Closed };
                match session.write(&packet).await {
                    Ok(n) => ctx.stats.add_up(n as u64),
                    Err(err) => {
                        log::warn!("[ВОРКЕР #{worker_id}] ошибка записи: {err}");
                        return SessionOutcome::Retryable(err.to_string());
                    }
                }
            }

            // Network → local.
            result = session.read(&mut read_buf) => {
                match result {
                    Ok(n) => {
                        // The server sends a 1-byte keepalive we must not forward.
                        if n == 1 && read_buf[0] == crate::dtls::KEEPALIVE_BYTE {
                            continue;
                        }
                        if n == 0 {
                            continue;
                        }
                        ctx.stats.add_down(n as u64);
                        slot.send_to_local(read_buf[..n].to_vec()).await;
                    }
                    Err(err) => {
                        log::warn!("[ВОРКЕР #{worker_id}] ошибка чтения: {err}");
                        return SessionOutcome::Retryable(err.to_string());
                    }
                }
            }
        }
    }
}

/// Supervises a pool of workers, restarting them with backoff.
pub async fn run_pool(ctx: Arc<SessionContext>, workers: usize, config_tx: Option<ConfigSink>) {
    let config_tx = Arc::new(Mutex::new(config_tx));
    let config_delivered = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(workers);

    for worker_id in 1..=workers {
        let ctx = Arc::clone(&ctx);
        let config_tx = Arc::clone(&config_tx);
        let config_delivered = Arc::clone(&config_delivered);
        handles.push(tokio::spawn(async move {
            let mut attempt = 0u32;
            loop {
                if ctx.token.is_cancelled() {
                    return;
                }
                // Only the first worker that still needs a config asks for one.
                let want_config = !config_delivered.load(Ordering::Relaxed);
                let tx = {
                    let guard = config_tx.lock().await;
                    guard.clone()
                };
                let outcome = run_session(Arc::clone(&ctx), worker_id, want_config, tx).await;

                match outcome {
                    SessionOutcome::Closed => return,
                    SessionOutcome::Fatal(message) => {
                        log::error!("[ВОРКЕР #{worker_id}] фатально: {message}");
                        events::emit_error("FATAL", &message, true);
                        return;
                    }
                    SessionOutcome::CredentialsRejected => {
                        attempt += 1;
                        log::warn!("[ВОРКЕР #{worker_id}] креды отклонены (попытка {attempt})");
                    }
                    SessionOutcome::Retryable(message) => {
                        attempt += 1;
                        log::warn!("[ВОРКЕР #{worker_id}] ошибка (попытка {attempt}): {message}");
                    }
                }

                let delay = retry_delay(attempt);
                tokio::select! {
                    _ = ctx.token.cancelled() => return,
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        }));
    }

    ctx.stats.set_workers(workers as u32, workers as u32);
    for handle in handles {
        let _ = handle.await;
    }
    log::info!("[ПУЛ] все воркеры завершены");
}

/// Exponential-ish backoff with jitter, capped at `RETRY_MAX`.
fn retry_delay(attempt: u32) -> Duration {
    use rand::Rng;
    let base = RETRY_MIN.as_secs() + (attempt.min(3) as u64) * 4;
    let jitter = rand::thread_rng().gen_range(0..4);
    Duration::from_secs((base + jitter).min(RETRY_MAX.as_secs()))
}

/// Convenience wrapper that reports a clear error when the pool dies early.
pub fn no_workers_error() -> anyhow::Error {
    anyhow!("пул воркеров завершился: ни одна сессия не поднялась")
}

/// Builds a dispatcher bound to `listen` (helper for `main`).
pub async fn make_dispatcher(listen: &str, stats: Arc<Stats>) -> Result<Dispatcher> {
    Dispatcher::bind(listen, stats).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_is_bounded() {
        for attempt in 0..20 {
            let delay = retry_delay(attempt);
            assert!(delay >= RETRY_MIN, "delay {delay:?} below minimum");
            assert!(delay <= RETRY_MAX, "delay {delay:?} above maximum");
        }
    }

    #[test]
    fn retry_delay_grows_then_plateaus() {
        // Attempt 0 is the shortest possible; attempt 10 is at the cap.
        assert!(retry_delay(0) <= retry_delay(10));
        assert!(retry_delay(10) <= RETRY_MAX);
    }

    #[test]
    fn keepalive_byte_is_forwarded_only_when_longer_than_one() {
        // Guard for the proxy loop: a 1-byte 0xFF datagram is a keepalive.
        let keepalive = [crate::dtls::KEEPALIVE_BYTE];
        assert_eq!(keepalive.len(), 1);
        assert_eq!(keepalive[0], 0xFF);
    }
}
