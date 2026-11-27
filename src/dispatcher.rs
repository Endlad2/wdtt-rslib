// SPDX-License-Identifier: LGPL-2.1
//
//! Local packet dispatcher.
//!
//! WireGuard sees a single UDP endpoint (`127.0.0.1:<local_port>`), but the
//! transport is spread over N DTLS sessions ("workers"). The dispatcher owns
//! the local UDP socket and round-robins outgoing datagrams across workers in
//! chunks, exactly like the reference client (12 datagrams per worker before
//! moving on), which keeps per-worker DTLS record ordering intact while still
//! using the whole pool.
//!
//! Return traffic is written back to the most recent local peer.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::stats::Stats;

/// Datagrams sent to one worker before switching to the next.
pub const CHUNK_SIZE: usize = 12;
/// Per-worker send queue depth.
pub const WORKER_QUEUE: usize = 128;
/// Socket buffer size, matching the reference client.
const SOCKET_BUF: usize = 625 * 1024;

/// Handle a worker uses to receive and send packets.
pub struct WorkerSlot {
    pub id: usize,
    pub send_rx: mpsc::Receiver<Vec<u8>>,
    return_tx: mpsc::Sender<Vec<u8>>,
}

impl WorkerSlot {
    /// Queues a datagram received from the network for the local peer.
    pub async fn send_to_local(&self, packet: Vec<u8>) {
        // If the writer is gone the tunnel is shutting down; dropping is fine.
        let _ = self.return_tx.try_send(packet);
    }
}

/// Shared, cloneable view of the dispatcher used by workers.
#[derive(Clone)]
pub struct DispatcherHandle {
    slots: Arc<Mutex<Vec<Arc<WorkerSend>>>>,
    round_robin: Arc<AtomicUsize>,
    chunk_count: Arc<AtomicUsize>,
    /// Single return path: every worker writes here, one writer drains it.
    return_tx: mpsc::Sender<Vec<u8>>,
}

struct WorkerSend {
    id: usize,
    tx: mpsc::Sender<Vec<u8>>,
}

impl DispatcherHandle {
    /// Sends a datagram to a worker, honouring the chunked round-robin policy.
    ///
    /// Returns `false` when every worker queue is full (the packet is dropped,
    /// which is what a congested VPN link should do).
    pub fn dispatch(&self, packet: Vec<u8>) -> bool {
        let slots = match self.slots.try_lock() {
            Ok(slots) => slots,
            Err(_) => return false,
        };
        if slots.is_empty() {
            return false;
        }
        let count = slots.len();
        let index = self.round_robin.load(Ordering::Relaxed) % count;

        // Try the current worker first, then every other one.
        let mut packet = packet;
        for offset in 0..count {
            let idx = (index + offset) % count;
            match slots[idx].tx.try_send(packet) {
                Ok(()) => {
                    if offset == 0 {
                        // Stay on this worker until the chunk is exhausted.
                        let sent = self.chunk_count.fetch_add(1, Ordering::Relaxed) + 1;
                        if sent >= CHUNK_SIZE {
                            self.round_robin.store((idx + 1) % count, Ordering::Relaxed);
                            self.chunk_count.store(0, Ordering::Relaxed);
                        }
                    } else {
                        // The current worker was backed up; continue from here.
                        self.round_robin.store(idx, Ordering::Relaxed);
                        self.chunk_count.store(1, Ordering::Relaxed);
                    }
                    return true;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(returned)) => {
                    packet = returned;
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return false,
            }
        }
        false
    }

    /// Registers a worker; returns its slot.
    pub async fn register(&self, id: usize) -> WorkerSlot {
        let (send_tx, send_rx) = mpsc::channel(WORKER_QUEUE);
        self.slots
            .lock()
            .await
            .push(Arc::new(WorkerSend { id, tx: send_tx }));
        log::info!(
            "[ДИСП] воркер #{id} зарегистрирован (всего: {})",
            self.slots.lock().await.len()
        );
        WorkerSlot {
            id,
            send_rx,
            return_tx: self.return_tx.clone(),
        }
    }

    /// Removes a worker slot.
    pub async fn unregister(&self, id: usize) {
        let mut slots = self.slots.lock().await;
        slots.retain(|slot| slot.id != id);
        log::info!("[ДИСП] воркер #{id} отключён (осталось: {})", slots.len());
    }

    /// Number of currently registered workers.
    pub async fn worker_count(&self) -> usize {
        self.slots.lock().await.len()
    }
}

/// The dispatcher: owns the local UDP socket and the worker registry.
pub struct Dispatcher {
    handle: DispatcherHandle,
    local_addr: SocketAddr,
    stats: Arc<Stats>,
    shutdown: tokio_util::sync::CancellationToken,
}

impl Dispatcher {
    /// Binds the local UDP socket and starts the return-path writer.
    pub async fn bind(listen: &str, stats: Arc<Stats>) -> Result<Self> {
        let socket = UdpSocket::bind(listen)
            .await
            .with_context(|| format!("binding the local WireGuard endpoint {listen}"))?;
        set_buffers(&socket);
        let local_addr = socket.local_addr().context("local endpoint address")?;

        // One return channel shared by every worker: the writer task below
        // drains it and forwards packets to the local peer.
        let (return_tx, mut return_rx) = mpsc::channel::<Vec<u8>>(512);

        let handle = DispatcherHandle {
            slots: Arc::new(Mutex::new(Vec::new())),
            round_robin: Arc::new(AtomicUsize::new(0)),
            chunk_count: Arc::new(AtomicUsize::new(0)),
            return_tx: return_tx.clone(),
        };

        let dispatcher = Dispatcher {
            handle: handle.clone(),
            local_addr,
            stats: Arc::clone(&stats),
            shutdown: tokio_util::sync::CancellationToken::new(),
        };

        // Return path: worker → local peer.
        let socket = Arc::new(socket);
        let token = dispatcher.shutdown.clone();
        let stats_ret = Arc::clone(&dispatcher.stats);
        let last_peer = Arc::new(Mutex::new(None::<SocketAddr>));

        // Writer task.
        {
            let socket = Arc::clone(&socket);
            let token = token.clone();
            let last_peer = Arc::clone(&last_peer);
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        packet = return_rx.recv() => {
                            let Some(packet) = packet else { break };
                            let peer = *last_peer.lock().await;
                            if let Some(peer) = peer {
                                if socket.send_to(&packet, peer).await.is_ok() {
                                    stats_ret.add_down(packet.len() as u64);
                                }
                            }
                        }
                    }
                }
            });
        }

        // Reader task: local peer → workers.
        {
            let socket = Arc::clone(&socket);
            let token = token.clone();
            let handle = handle.clone();
            let last_peer = Arc::clone(&last_peer);
            let stats_up = Arc::clone(&stats);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        result = socket.recv_from(&mut buf) => {
                            let Ok((n, peer)) = result else { continue };
                            if n == 0 {
                                continue;
                            }
                            *last_peer.lock().await = Some(peer);
                            let _ = return_tx.clone();
                            if !handle.dispatch(buf[..n].to_vec()) {
                                log::trace!("all worker queues are full; dropping a packet");
                            } else {
                                stats_up.add_up(n as u64);
                            }
                        }
                    }
                }
            });
        }

        Ok(dispatcher)
    }

    pub fn handle(&self) -> DispatcherHandle {
        self.handle.clone()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    pub fn shutdown_token(&self) -> tokio_util::sync::CancellationToken {
        self.shutdown.clone()
    }

    /// Stops the dispatcher loops.
    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }
}

fn set_buffers(socket: &UdpSocket) {
    let sock = socket2::SockRef::from(socket);
    let _ = sock.set_recv_buffer_size(SOCKET_BUF);
    let _ = sock.set_send_buffer_size(SOCKET_BUF);
}

/// Total traffic formatted for logs.
pub fn traffic_summary(stats: &Stats) -> String {
    format!(
        "активных: {} | отправлено: {} | получено: {}",
        stats.active(),
        crate::stats::format_mb(stats.bytes_up()),
        crate::stats::format_mb(stats.bytes_down())
    )
}

/// Periodically logs and emits traffic statistics.
pub async fn stats_loop(stats: Arc<Stats>, token: tokio_util::sync::CancellationToken) {
    let mut ticker = tokio::time::interval(Duration::from_secs(3));
    let mut last_up = 0u64;
    let mut last_down = 0u64;
    loop {
        tokio::select! {
            _ = token.cancelled() => return,
            _ = ticker.tick() => {
                let up = stats.bytes_up();
                let down = stats.bytes_down();
                stats.set_rates(up.saturating_sub(last_up) / 3, down.saturating_sub(last_down) / 3);
                last_up = up;
                last_down = down;
                log::info!("[СТАТИСТИКА] {}", traffic_summary(&stats));
                crate::events::emit_stats(&stats);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dispatcher_round_robins_in_chunks() {
        let stats = Stats::new();
        let dispatcher = Dispatcher::bind("127.0.0.1:0", stats.clone())
            .await
            .expect("bind");

        let mut a = dispatcher.handle().register(1).await;
        let mut b = dispatcher.handle().register(2).await;
        let handle = dispatcher.handle();

        // The first CHUNK_SIZE packets go to worker 1, the next to worker 2.
        for i in 0..CHUNK_SIZE {
            assert!(handle.dispatch(vec![i as u8]), "dispatch {i}");
        }
        let mut first = Vec::new();
        while let Ok(p) = a.send_rx.try_recv() {
            first.push(p);
        }
        assert_eq!(
            first.len(),
            CHUNK_SIZE,
            "first worker must get a full chunk"
        );

        for _ in 0..CHUNK_SIZE {
            assert!(handle.dispatch(vec![0]));
        }
        let mut second = Vec::new();
        while let Ok(p) = b.send_rx.try_recv() {
            second.push(p);
        }
        assert_eq!(
            second.len(),
            CHUNK_SIZE,
            "second worker must get the next chunk"
        );

        dispatcher.shutdown();
    }

    #[tokio::test]
    async fn dispatcher_drops_when_no_workers() {
        let stats = Stats::new();
        let dispatcher = Dispatcher::bind("127.0.0.1:0", stats).await.expect("bind");
        assert!(!dispatcher.handle().dispatch(vec![1, 2, 3]));
        dispatcher.shutdown();
    }

    #[tokio::test]
    async fn dispatcher_unregisters_workers() {
        let stats = Stats::new();
        let dispatcher = Dispatcher::bind("127.0.0.1:0", stats).await.expect("bind");
        let _slot = dispatcher.handle().register(7).await;
        assert_eq!(dispatcher.handle().worker_count().await, 1);
        dispatcher.handle().unregister(7).await;
        assert_eq!(dispatcher.handle().worker_count().await, 0);
        dispatcher.shutdown();
    }
}
