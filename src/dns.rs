use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::task;

// DNS-серверы для проверки
pub const YANDEX_DNS_SERVERS: [&str; 2] = ["77.88.8.8:53", "77.88.8.1:53"];
pub const CLOUDFLARE_DNS_SERVERS: [&str; 2] = ["1.1.1.1:53", "1.0.0.1:53"];
pub const GOOGLE_DNS_SERVERS: [&str; 2] = ["8.8.8.8:53", "8.8.4.4:53"];

// Для обратной совместимости
pub const YANDEX_DNSSERVERS: [&str; 2] = YANDEX_DNS_SERVERS;

static FASTEST_DNS: OnceLock<String> = OnceLock::new();

/// Проверяет доступность DNS-сервера и возвращает время ответа в миллисекундах
fn check_dns_server(server: &str, domain: &str) -> Option<u64> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return None,
    };

    if let Err(_) = socket.set_read_timeout(Some(Duration::from_secs(2))) {
        return None;
    }

    let server_addr: SocketAddr = match server.to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => return None,
        },
        Err(_) => return None,
    };

    let query = build_dns_query(domain);

    let start = Instant::now();

    if let Err(_) = socket.send_to(&query, server_addr) {
        return None;
    }

    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((_size, _addr)) => {
            let elapsed = start.elapsed();
            Some(elapsed.as_millis() as u64)
        }
        Err(_) => None,
    }
}

/// Строит простой DNS-запрос (A-запрос)
fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut query = Vec::new();

    // Transaction ID (0x1234)
    query.extend_from_slice(&[0x12, 0x34]);

    // Flags: стандартный запрос
    query.extend_from_slice(&[0x01, 0x00]);

    // Questions: 1
    query.extend_from_slice(&[0x00, 0x01]);

    // Answer RRs: 0
    query.extend_from_slice(&[0x00, 0x00]);

    // Authority RRs: 0
    query.extend_from_slice(&[0x00, 0x00]);

    // Additional RRs: 0
    query.extend_from_slice(&[0x00, 0x00]);

    // Domain name
    for part in domain.split('.') {
        query.push(part.len() as u8);
        query.extend_from_slice(part.as_bytes());
    }
    query.push(0);

    // Type: A (1)
    query.extend_from_slice(&[0x00, 0x01]);

    // Class: IN (1)
    query.extend_from_slice(&[0x00, 0x01]);

    query
}

/// Проверяет все DNS-серверы параллельно и возвращает самый быстрый
pub async fn find_fastest_dns(domain: &str) -> String {
    // Если уже есть сохранённый быстрый DNS
    if let Some(cached) = FASTEST_DNS.get() {
        // Проверяем, что он ещё работает
        if let Some(_) = check_dns_server(cached, domain) {
            return cached.clone();
        }
        // Если не работает, очищаем кэш (просто игнорируем)
    }

    let all_servers: Vec<&str> = [
        YANDEX_DNS_SERVERS.as_slice(),
        CLOUDFLARE_DNS_SERVERS.as_slice(),
        GOOGLE_DNS_SERVERS.as_slice(),
    ]
    .concat();

    let domain = domain.to_string();

    // Проверяем параллельно
    let mut tasks = Vec::new();

    // ✅ ИСПРАВЛЕНО: используем for server in &all_servers
    for server in &all_servers {
        let server = (*server).to_string();
        let domain = domain.clone();

        let task = task::spawn_blocking(move || {
            let result = check_dns_server(&server, &domain);
            (server, result)
        });

        tasks.push(task);
    }

    let mut results = Vec::new();
    for task in tasks {
        if let Ok((server, Some(time))) = task.await {
            results.push((server, time));
        }
    }

    results.sort_by_key(|(_, time)| *time);

    if let Some((fastest, time)) = results.first() {
        let fastest = fastest.clone();
        let _ = FASTEST_DNS.set(fastest.clone());
        eprintln!("[DNS] Выбран быстрый DNS: {} ({}ms)", fastest, time);
        return fastest;
    }

    eprintln!("[DNS] Не удалось найти рабочий DNS, используем Яндекс DNS");
    YANDEX_DNS_SERVERS[0].to_string()
}

/// Настраивает глобальный DNS-резолвер
pub fn setupGlobalResolver() {
    let domain = "vk.com".to_string();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let fastest = find_fastest_dns(&domain).await;
            eprintln!("[DNS] Глобальный резолвер настроен на {}", fastest);

            // Проверяем доступность DNS
            std::thread::spawn(move || {
                let addr = format!("{}:53", fastest);
                if let Ok(mut addrs) = addr.to_socket_addrs() {
                    if let Some(_addr) = addrs.next() {
                        eprintln!("[DNS] DNS-сервер {} доступен", fastest);
                    }
                }
            });
        });
    });
}

pub fn isYandexDNSAddress(address: &str) -> bool {
    let h = address
        .trim()
        .trim_start_matches('[')
        .split([':', ']'])
        .next()
        .unwrap_or("");
    h == "77.88.8.8" || h == "77.88.8.1"
}

/// Синхронная проверка DNS-серверов
pub fn check_dns_servers_sync(domain: &str) -> String {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(find_fastest_dns(domain))
}