use std::sync::atomic::{AtomicI32, AtomicI64, Ordering}; use tokio::sync::watch; use std::time::Duration;
pub struct Stats { pub TotalBytesUp: AtomicI64, pub TotalBytesDown: AtomicI64, pub ActiveConnections: AtomicI32 }
pub fn NewStats() -> Stats { Stats { TotalBytesUp:AtomicI64::new(0), TotalBytesDown:AtomicI64::new(0), ActiveConnections:AtomicI32::new(0) } }
impl Stats { pub async fn RunLoop(&self, mut shutdown: watch::Receiver<bool>) { loop { tokio::select! { _=shutdown.changed()=>return, _=tokio::time::sleep(Duration::from_secs(3))=> { eprintln!("[СТАТИСТИКА] Активных: {} | Трафик: {:.2} МБ",self.ActiveConnections.load(Ordering::Relaxed),(self.TotalBytesUp.load(Ordering::Relaxed)+self.TotalBytesDown.load(Ordering::Relaxed)) as f64/1048576.0); crate::events::emitStats(self); } } } } }
