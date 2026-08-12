use std::{collections::HashSet, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use crate::{dispatcher::Dispatcher, session::RunSession, stats::Stats, vk_auth::GetCreds};

pub const workersPerGroup: usize = 9;
pub const defaultCycleSecs: u64 = 36000;

#[derive(Clone, Debug)]
pub struct TurnParams {
    pub Host: String,
    pub Port: String,
    pub Hashes: Vec<String>,
    pub WrapKey: Vec<u8>,
    pub ObfsMode: String,
}

#[derive(Clone, Debug)]
pub struct Credentials {
    pub User: String,
    pub Pass: String,
    pub TurnURLs: Vec<String>,
    pub CacheStreamID: i32,
}

pub fn normalizeVKJoinHash(input: &str) -> String {
    let mut s = input.trim().trim_matches(|c| matches!(c, '<' | '>' | '\"' | '\'')).to_string();
    if s.is_empty() {
        return s;
    };
    let l = s.to_lowercase();
    if let Some(i) = l.find("/call/join/") {
        s = s[i + 11..].into();
    } else if l.starts_with("http://") || l.starts_with("https://") {
        return String::new();
    }
    if let Some(i) = s.find(|c| matches!(c, '?' | '#' | '/')) {
        s.truncate(i);
    }
    s.trim().trim_matches('/').into()
}

pub fn ParseHashes(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    raw.split(|c: char| matches!(c, ',' | ';' | '\n' | '\r' | '\t' | ' '))
        .filter_map(|h| {
            let h = normalizeVKJoinHash(h);
            if !h.is_empty() && seen.insert(h.clone()) {
                Some(h)
            } else {
                None
            }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub async fn WorkerGroup(
    cancel: CancellationToken,
    group_id: i32,
    hash_index: usize,
    params: Arc<TurnParams>,
    peer: String,
    dispatcher: Arc<Dispatcher>,
    local_port: String,
    get_config: bool,
    config_tx: mpsc::Sender<String>,
    worker_ids: Vec<i32>,
    paused: Arc<AtomicBool>,
    device_id: String,
    password: String,
    stats: Arc<Stats>,
) {
    while paused.load(Ordering::Relaxed) {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }

    let Some(hash) = params.Hashes.get(hash_index % params.Hashes.len()).cloned() else {
        return;
    };

    let stream_id = group_id * 100;
    eprintln!("[ГРУППА #{}] Запрос кредов (хеш: {}...)", group_id, &hash[..hash.len().min(8)]);

    let credentials = match GetCreds(&hash, stream_id).await {
        Ok((user, pass, urls)) => {
            eprintln!("[ГРУППА #{}] Креды получены, TURN urls={}", group_id, urls.len());
            Credentials {
                User: user,
                Pass: pass,
                TurnURLs: urls,
                CacheStreamID: stream_id,
            }
        }
        Err(e) => {
            eprintln!("[ГРУППА #{}] ❌ Ошибка получения кредов: {}", group_id, e);
            return;
        }
    };

    let config_once = Arc::new(AtomicBool::new(get_config));
    let mut handles = Vec::with_capacity(worker_ids.len());

    for worker_id in worker_ids {
        let cancel = cancel.clone();
        let params = params.clone();
        let peer = peer.clone();
        let dispatcher = dispatcher.clone();
        let port = local_port.clone();
        let device_id = device_id.clone();
        let password = password.clone();
        let credentials = credentials.clone();
        let tx = config_tx.clone();
        let config_once = config_once.clone();
        let paused = paused.clone();
        let stats = stats.clone();

        let handle = tokio::spawn(async move {
            let mut attempt = 0;
            loop {
                if cancel.is_cancelled() {
                    return;
                }

                while paused.load(Ordering::Relaxed) {
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                }

                attempt += 1;
                let want_config = config_once.swap(false, Ordering::AcqRel);
                
                eprintln!("[ВОРКЕР #{}] Попытка {}...", worker_id, attempt);

                let result = RunSession(
                    &params,
                    &peer,
                    dispatcher.clone(),
                    &port,
                    want_config,
                    if want_config { Some(tx.clone()) } else { None },
                    worker_id,
                    &credentials,
                    &device_id,
                    &password,
                    stats.clone(),
                ).await;

                match result {
                    Ok(config_delivered) => {
                        if config_delivered {
                            eprintln!("[ВОРКЕР #{}] ✅ Конфиг получен", worker_id);
                        } else {
                            eprintln!("[ВОРКЕР #{}] ✅ Подключён к TURN", worker_id);
                        }
                        // Успешное подключение - сбрасываем счётчик попыток
                        attempt = 0;
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("FATAL_AUTH") {
                            eprintln!("[ВОРКЕР #{}] ❌ Фатальная ошибка: {}", worker_id, err_str);
                            cancel.cancel();
                            return;
                        }
                        
                        if err_str.contains("TURN Allocate") {
                            eprintln!("[ВОРКЕР #{}] ❌ TURN Allocate (попытка {}): {}", worker_id, attempt, err_str);
                        } else if err_str.contains("DTLS timeout") {
                            eprintln!("[ВОРКЕР #{}] ❌ DTLS timeout (попытка {})", worker_id, attempt);
                        } else {
                            eprintln!("[ВОРКЕР #{}] ❌ Ошибка (попытка {}): {}", worker_id, attempt, err_str);
                        }
                    }
                }

                // Задержка перед следующей попыткой (увеличивается с каждой попыткой)
                let delay = if attempt > 5 {
                    Duration::from_secs(5)
                } else if attempt > 3 {
                    Duration::from_secs(3)
                } else {
                    Duration::from_secs(2)
                };

                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(delay) => {}
                }
            }
        });

        handles.push(handle);
        // Пауза между запусками воркеров (200ms)
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    for h in handles {
        let _ = h.await;
    }
    
    eprintln!("[ГРУППА #{}] Все воркеры завершены", group_id);
}