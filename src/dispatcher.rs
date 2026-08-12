use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, watch};
use crate::stats::Stats;

pub const RETURN_CH_BUF: usize = 512;
pub const CHUNK_SIZE: usize = 12;
pub const PKT_BUF_SIZE: usize = 2048;

// Пул буферов (аналог sync.Pool из Go)
pub fn getPktBuf(size: usize) -> Vec<u8> {
    if size <= PKT_BUF_SIZE {
        if let Some(mut buf) = PKT_POOL.try_lock().ok().and_then(|mut pool| pool.pop()) {
            buf.resize(size, 0);
            return buf;
        }
    }
    vec![0; size]
}

pub fn putPktBuf(mut buf: Vec<u8>) {
    if buf.capacity() <= PKT_BUF_SIZE {
        if let Ok(mut pool) = PKT_POOL.try_lock() {
            if pool.len() < 100 {
                buf.clear();
                pool.push(buf);
            }
        }
    }
}

static PKT_POOL: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());

pub struct WorkerSlot {
    pub ID: i32,
    pub SendCh: mpsc::Sender<Vec<u8>>,
}

pub struct Dispatcher {
    pub localConn: Arc<UdpSocket>,
    clientAddr: RwLock<Option<SocketAddr>>,
    workers: RwLock<Vec<Arc<WorkerSlot>>>,
    rrIndex: AtomicUsize,
    pub ReturnCh: mpsc::Sender<Vec<u8>>,
    returnRx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    shutdown: watch::Sender<bool>,
    stats: Arc<Stats>,
}

pub async fn NewDispatcher(
    localConn: UdpSocket,
    stats: Arc<Stats>,
) -> Arc<Dispatcher> {
    let (tx, rx) = mpsc::channel(RETURN_CH_BUF);
    let (shutdown, _) = watch::channel(false);
    
    Arc::new(Dispatcher {
        localConn: Arc::new(localConn),
        clientAddr: RwLock::new(None),
        workers: RwLock::new(vec![]),
        rrIndex: AtomicUsize::new(0),
        ReturnCh: tx,
        returnRx: tokio::sync::Mutex::new(rx),
        shutdown,
        stats,
    })
}

impl Dispatcher {
    pub async fn Shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    pub async fn Register(&self, w: Arc<WorkerSlot>) {
        let id = w.ID;
        self.workers.write().await.push(w);
        let count = self.workers.read().await.len();
        eprintln!("[ДИСП] Воркер #{} зарегистрирован (всего: {})", id, count);
    }

    pub async fn Unregister(&self, id: i32) {
        let _count_before = self.workers.read().await.len();
        self.workers.write().await.retain(|w| w.ID != id);
        let count_after = self.workers.read().await.len();
        eprintln!("[ДИСП] Воркер #{} отключён (осталось: {})", id, count_after);
    }

    pub async fn readLoop(self: Arc<Self>) {
        let mut b = [0u8; PKT_BUF_SIZE];
        
        loop {
            let (n, addr) = match self.localConn.recv_from(&mut b).await {
                Ok(result) => result,
                Err(_) => {
                    if self.shutdown_closed().await {
                        return;
                    }
                    continue;
                }
            };

            *self.clientAddr.write().await = Some(addr);
            self.stats.TotalBytesUp.fetch_add(n as i64, Ordering::Relaxed);

            let data = b[..n].to_vec();

            let workers = self.workers.read().await;
            if workers.is_empty() {
                continue;
            }

            let idx = self.rrIndex.fetch_add(1, Ordering::Relaxed) / CHUNK_SIZE % workers.len();
            
            if let Some(w) = workers.get(idx) {
                // Пробуем отправить первому воркеру
                if w.SendCh.try_send(data.clone()).is_err() {
                    // Если не получилось, пробуем следующие
                    for i in 1..workers.len() {
                        let next_idx = (idx + i) % workers.len();
                        if let Some(next) = workers.get(next_idx) {
                            if next.SendCh.try_send(data.clone()).is_ok() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    pub async fn writeLoop(self: Arc<Self>) {
        loop {
            let p = {
                let mut rx = self.returnRx.lock().await;
                rx.recv().await
            };

            let Some(p) = p else {
                return;
            };

            let addr = {
                let guard = self.clientAddr.read().await;
                *guard
            };

            if let Some(addr) = addr {
                if let Err(_) = self.localConn.send_to(&p, addr).await {
                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    let _ = self.localConn.send_to(&p, addr).await;
                }
                self.stats.TotalBytesDown.fetch_add(p.len() as i64, Ordering::Relaxed);
            }
        }
    }

    async fn shutdown_closed(&self) -> bool {
        let mut rx = self.shutdown.subscribe();
        rx.changed().await.is_ok()
    }
}