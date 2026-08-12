#![allow(non_snake_case)]
use anyhow::{bail, Context, Result};
use std::sync::{Arc, LazyLock, RwLock, atomic::{AtomicBool, Ordering}};
use tokio::{io::{AsyncBufReadExt, BufReader}, net::UdpSocket, sync::mpsc};
use tokio_util::sync::CancellationToken;
use wdtt_rslib::{dispatcher::NewDispatcher, events::{emitConfig, emitEvent, eventStarted, eventStopped}, profiles::SetActiveFingerprint, stats::NewStats, worker_group::{ParseHashes, TurnParams, WorkerGroup, workersPerGroup}, wrap::deriveWrapKey};

static captchaModeValue: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new("auto".into()));
static vkAuthModeValue: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new("vkcalls".into()));

pub fn normalizeCaptchaMode(mode: &str) -> String {
    match mode.trim().to_lowercase().as_str() {
        "auto" | "rjs" | "wv" => mode.trim().to_lowercase(),
        _ => "auto".into()
    }
}

pub fn setCaptchaMode(mode: &str) -> String {
    let x = normalizeCaptchaMode(mode);
    *captchaModeValue.write().unwrap() = x.clone();
    x
}

pub fn getCaptchaMode() -> String {
    captchaModeValue.read().unwrap().clone()
}

pub fn normalizeVKAuthMode(mode: &str) -> String {
    if mode.trim().eq_ignore_ascii_case("legacy") {
        "legacy".into()
    } else {
        "vkcalls".into()
    }
}

pub fn setVKAuthMode(mode: &str) -> String {
    let x = normalizeVKAuthMode(mode);
    *vkAuthModeValue.write().unwrap() = x.clone();
    x
}

pub fn getVKAuthMode() -> String {
    vkAuthModeValue.read().unwrap().clone()
}

#[derive(Default)]
struct Args {
    turn: String,
    port: String,
    listen: String,
    vk: String,
    peer: String,
    n: usize,
    device_id: String,
    password: String,
    obfs: String,
    fingerprint: String,
    captcha: String,
    vk_auth: String,
    client_ids: String,
}

fn args() -> Result<Args> {
    let mut a = Args {
        listen: "127.0.0.1:9000".into(),
        n: 24,
        device_id: "unknown".into(),
        obfs: "audio".into(),
        fingerprint: "chrome".into(),
        captcha: "auto".into(),
        vk_auth: "vkcalls".into(),
        ..Default::default()
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let v = it.next().with_context(|| format!("нет значения для {k}"))?;
        match k.as_str() {
            "-turn" => a.turn = v,
            "-port" => a.port = v,
            "-listen" => a.listen = v,
            "-vk" => a.vk = v,
            "-peer" => a.peer = v,
            "-n" => a.n = v.parse().context("-n")?,
            "-device-id" => a.device_id = v,
            "-password" => a.password = v,
            "-obfs" => a.obfs = v,
            "-fingerprint" => a.fingerprint = v,
            "-captcha-mode" => a.captcha = v,
            "-vk-auth-mode" => a.vk_auth = v,
            "-client-ids" => a.client_ids = v,
            _ => bail!("неизвестный аргумент: {k}"),
        }
    }
    Ok(a)
}

fn save_config_to_file(config: &str) -> Result<()> {
    use std::fs;
    
    let mut result = String::new();
    let lines: Vec<&str> = config.lines().collect();
    
    let mut in_interface = false;
    let mut in_peer = false;
    let mut has_interface_mtu = false;
    let mut has_peer_allowed_ips = false;
    let mut has_endpoint = false;
    
    for line in &lines {
        let trimmed = line.trim();
        
        if trimmed == "[Interface]" {
            in_interface = true;
            in_peer = false;
            result.push_str(line);
            result.push('\n');
            continue;
        }
        
        if trimmed == "[Peer]" {
            in_interface = false;
            in_peer = true;
            result.push_str(line);
            result.push('\n');
            continue;
        }
        
        if in_interface && trimmed.starts_with("MTU =") {
            has_interface_mtu = true;
            result.push_str("MTU = 1280\n");
            continue;
        }
        
        if in_peer && trimmed.starts_with("AllowedIPs =") {
            has_peer_allowed_ips = true;
            // Используем готовый список AllowedIPs из конфига
            result.push_str("AllowedIPs = 0.0.0.0/6, 4.0.0.0/8, 5.0.0.0/11, 5.32.0.0/12, 5.48.0.0/13, 5.56.0.0/14, 5.60.0.0/16, 5.61.0.0/20, 5.61.24.0/21, 5.61.32.0/19, 5.61.64.0/18, 5.61.128.0/18, 5.61.192.0/19, 5.61.224.0/21, 5.61.240.0/20, 5.62.0.0/15, 5.64.0.0/11, 5.96.0.0/14, 5.100.0.0/16, 5.101.0.0/19, 5.101.32.0/21, 5.101.44.0/22, 5.101.48.0/20, 5.101.64.0/18, 5.101.128.0/17, 5.102.0.0/15, 5.104.0.0/13, 5.112.0.0/12, 5.128.0.0/11, 5.160.0.0/12, 5.176.0.0/14, 5.180.0.0/16, 5.181.0.0/19, 5.181.32.0/20, 5.181.48.0/21, 5.181.56.0/22, 5.181.64.0/18, 5.181.128.0/17, 5.182.0.0/15, 5.184.0.0/14, 5.188.0.0/17, 5.188.128.0/21, 5.188.136.0/22, 5.188.144.0/20, 5.188.160.0/19, 5.188.192.0/18, 5.189.0.0/16, 5.190.0.0/15, 5.192.0.0/10\n");
            continue;
        }
        
        if in_peer && trimmed.starts_with("Endpoint =") {
            has_endpoint = true;
            result.push_str("Endpoint = 127.0.0.1:9000\n");
            continue;
        }
        
        result.push_str(line);
        result.push('\n');
    }
    
    if !has_interface_mtu {
        let mut new_result = String::new();
        for line in result.lines() {
            new_result.push_str(line);
            new_result.push('\n');
            if line.trim() == "[Interface]" {
                new_result.push_str("MTU = 1280\n");
            }
        }
        result = new_result;
    }
    
    if !has_endpoint {
        let mut new_result = String::new();
        let mut peer_found = false;
        for line in result.lines() {
            new_result.push_str(line);
            new_result.push('\n');
            if line.trim() == "[Peer]" && !peer_found {
                peer_found = true;
                new_result.push_str("Endpoint = 127.0.0.1:9000\n");
            }
        }
        result = new_result;
    }
    
    fs::write("config.toml", result)?;
    eprintln!("[КОНФИГ] Сохранён в config.toml (MTU=1280, Endpoint=127.0.0.1:9000)");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let a = args()?;
    if a.peer.is_empty() || a.vk.is_empty() {
        bail!("Нужны -peer и -vk");
    }
    if a.password.is_empty() {
        bail!("Нужен -password");
    };

    let hashes = ParseHashes(&a.vk);
    if hashes.is_empty() {
        bail!("Нет хешей VK");
    };

    SetActiveFingerprint(&a.fingerprint);
    setCaptchaMode(&a.captcha);
    setVKAuthMode(&a.vk_auth);

    if !a.client_ids.is_empty() {
        wdtt_rslib::vk_auth::SetActiveClientIds(&a.client_ids);
    }

    let key = deriveWrapKey(&a.password)?;
    let workers = a.n.clamp(workersPerGroup, 108) / workersPerGroup * workersPerGroup;

    let socket = UdpSocket::bind(&a.listen)
        .await
        .with_context(|| format!("бинд {}", a.listen))?;
    let port = socket.local_addr()?.port().to_string();

    let stats = Arc::new(NewStats());
    let dispatcher = NewDispatcher(socket, stats.clone()).await;

    tokio::spawn(dispatcher.clone().readLoop());
    tokio::spawn(dispatcher.clone().writeLoop());

    let cancel = CancellationToken::new();
    let paused = Arc::new(AtomicBool::new(false));

    let (config_tx, mut config_rx) = mpsc::channel(1);
    let params = Arc::new(TurnParams {
        Host: a.turn,
        Port: a.port,
        Hashes: hashes,
        WrapKey: key,
        ObfsMode: a.obfs,
    });

    eprintln!("[КЛИЕНТ] Слушаю {} | пир {} | воркеров {}", port, a.peer, workers);
    emitEvent(eventStarted, serde_json::json!({"listen_port": port, "workers": workers}));

    // ============================================================
    // ПОСТЕПЕННЫЙ ЗАПУСК ВОРКЕРОВ
    // ============================================================
    let num_groups = workers / workersPerGroup;
    let mut handles = Vec::new();

    let first_batch = 5;
    let first_groups = num_groups.min(first_batch / workersPerGroup + 1);
    
    eprintln!("[КЛИЕНТ] Запуск первых {} воркеров...", first_groups * workersPerGroup);
    
    for group in 0..first_groups {
        let ids: Vec<i32> = (0..workersPerGroup)
            .map(|n| (group * workersPerGroup + n) as i32)
            .collect();
        
        let handle = tokio::spawn(WorkerGroup(
            cancel.clone(),
            group as i32,
            group,
            params.clone(),
            a.peer.clone(),
            dispatcher.clone(),
            port.clone(),
            group == 0,
            config_tx.clone(),
            ids,
            paused.clone(),
            a.device_id.clone(),
            a.password.clone(),
            stats.clone(),
        ));
        handles.push(handle);
        
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }

    if first_groups < num_groups {
        eprintln!("[КЛИЕНТ] Ожидание 3 секунды перед запуском следующих воркеров...");
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    }

    let mut current_group = first_groups;
    while current_group < num_groups {
        let batch_end = (current_group + 4).min(num_groups);
        
        eprintln!("[КЛИЕНТ] Запуск групп {}-{} ({} воркеров)...", 
            current_group, batch_end - 1, (batch_end - current_group) * workersPerGroup);
        
        for group in current_group..batch_end {
            let ids: Vec<i32> = (0..workersPerGroup)
                .map(|n| (group * workersPerGroup + n) as i32)
                .collect();
            
            let handle = tokio::spawn(WorkerGroup(
                cancel.clone(),
                group as i32,
                group,
                params.clone(),
                a.peer.clone(),
                dispatcher.clone(),
                port.clone(),
                false,
                config_tx.clone(),
                ids,
                paused.clone(),
                a.device_id.clone(),
                a.password.clone(),
                stats.clone(),
            ));
            handles.push(handle);
            
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }
        
        current_group = batch_end;
        
        if current_group < num_groups {
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        }
    }

    eprintln!("[КЛИЕНТ] Все {} групп запущены ({} воркеров)", num_groups, workers);

    // Обработка событий - сохранение конфига в файл
    let event_cancel = cancel.clone();
    tokio::spawn(async move {
        while let Some(config) = config_rx.recv().await {
            if let Err(e) = save_config_to_file(&config) {
                eprintln!("[КОНФИГ] Ошибка сохранения: {}", e);
            }
            emitConfig(&config);
        }
    });

    // Обработка STDIN
    let stdin_cancel = cancel.clone();
    let stdin_pause = paused.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            match line.trim() {
                "PAUSE" => stdin_pause.store(true, Ordering::Relaxed),
                "RESUME" => stdin_pause.store(false, Ordering::Relaxed),
                "STOP" => {
                    stdin_cancel.cancel();
                    break;
                }
                _ => {}
            }
        }
    });

    // Ожидание сигнала завершения
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            eprintln!("[КЛИЕНТ] Получен Ctrl+C, завершаю...");
            cancel.cancel();
        }
        _ = cancel.cancelled() => {
            eprintln!("[КЛИЕНТ] Завершение по сигналу...");
        }
    }

    // Ждём завершения всех воркеров
    for handle in handles {
        let _ = handle.await;
    }

    dispatcher.Shutdown().await;
    emitEvent(eventStopped, serde_json::json!({}));
    
    eprintln!("[КЛИЕНТ] Все воркеры завершены");
    Ok(())
}