// SPDX-License-Identifier: LGPL-2.1
//
//! WDTToR — a Rust client for the WDTT protocol (WireGuard over TURN/DTLS),
//! backwards compatible with the original WDTT server.
//!
//! Two run modes:
//!
//! * **own TUN** (default on Linux/macOS/Windows): the client creates the
//!   tunnel interface itself, so the host only has to route traffic into it;
//! * **external TUN** (`--tun-fd-socket` / `--no-tun`): the host owns the
//!   interface (Android VpnService, iOS, or an already running WireGuard) and
//!   only needs the local WireGuard endpoint.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use wdtt_rslib::config::WdttLink;
use wdtt_rslib::dispatcher::{self, Dispatcher};
use wdtt_rslib::events;
use wdtt_rslib::obfs::ObfsMode;
use wdtt_rslib::session::{self, ConfigSink, CredentialCache, SessionContext};
use wdtt_rslib::stats::Stats;
use wdtt_rslib::wireguard::{self, WgTunnel};
use wdtt_rslib::wrap::derive_wrap_key;

/// Version reported by `--version` and in the STARTED event.
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug, Clone)]
#[command(
    name = "wdtt-rslib",
    about = "WDTToR — клиент WDTT (WireGuard поверх TURN/DTLS)",
    version
)]
pub struct Args {
    /// Ссылка wdtt://host:dtls:wg:local:password:hashes
    #[arg(long, value_name = "LINK")]
    pub link: Option<String>,

    /// Адрес сервера host:port (альтернатива --link)
    #[arg(long, value_name = "HOST:PORT")]
    pub peer: Option<String>,

    /// Пароль подключения (альтернатива --link)
    #[arg(long, value_name = "PASSWORD")]
    pub password: Option<String>,

    /// Хеши VK-звонков через запятую (альтернатива --link)
    #[arg(long, value_name = "HASHES")]
    pub vk: Option<String>,

    /// Количество воркеров (кратно 9, как в оригинале)
    #[arg(long, short = 'n', default_value_t = 9, value_name = "N")]
    pub workers: usize,

    /// Локальный адрес WireGuard-эндпоинта
    #[arg(long, default_value = "127.0.0.1:9000", value_name = "ADDR")]
    pub listen: String,

    /// Режим обфускации: audio или video
    #[arg(long, default_value = "audio", value_name = "MODE")]
    pub obfs: String,

    /// Как получать TURN-креды у VK: vkcalls (по умолчанию) или legacy
    #[arg(long, default_value = "vkcalls", value_name = "MODE")]
    pub vk_auth_mode: String,

    /// Идентификатор устройства (привязывается к паролю на сервере)
    #[arg(long, default_value = "wdtt-rs", value_name = "ID")]
    pub device_id: String,

    /// Переопределить IP TURN-сервера (отладка)
    #[arg(long, value_name = "HOST")]
    pub turn: Option<String>,

    /// Переопределить порт TURN-сервера (отладка)
    #[arg(long, value_name = "PORT")]
    pub port: Option<String>,

    /// Имя TUN-интерфейса для собственного режима
    #[arg(long, default_value = "wdtt0", value_name = "NAME")]
    pub tun_name: String,

    /// MTU для собственного TUN (по умолчанию из конфига сервера)
    #[arg(long, value_name = "MTU")]
    pub mtu: Option<u16>,

    /// Не поднимать TUN: только локальный WireGuard-эндпоинт
    #[arg(long)]
    pub no_tun: bool,

    /// Получить fd TUN из unix-сокета (Android/iOS)
    #[arg(long, value_name = "PATH")]
    pub tun_fd_socket: Option<String>,

    /// Отдавать сырые IP-пакеты по UDP вместо TUN (Android VpnService, iOS)
    ///
    /// Ядро слушает этот адрес: хост-приложение присылает сюда IP-пакеты из
    /// своего интерфейса, а ядро само делает WireGuard. Это единственный
    /// способ работать на Android без root: /dev/net/tun там недоступен.
    #[arg(long, value_name = "ADDR")]
    pub packet_port: Option<String>,

    /// Печатать машинные события __WDTT_EVENT__|...
    #[arg(long)]
    pub events: bool,

    /// Самопроверка: поднять туннель без TUN и пинговать сервер через него
    #[arg(long)]
    pub self_test: bool,

    /// Уровень логирования: error, warn, info, debug, trace
    #[arg(long, default_value = "info", value_name = "LEVEL")]
    pub log_level: String,
}

impl Args {
    /// Turns the CLI arguments into a `WdttLink`.
    pub fn to_link(&self) -> Result<WdttLink> {
        if let Some(link) = &self.link {
            return link.parse();
        }

        let peer = self
            .peer
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("нужен --link или --peer"))?;
        let password = self
            .password
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("нужен --password"))?;
        let hashes = self.vk.as_deref().unwrap_or("");
        if hashes.trim().is_empty() {
            bail!("нужен --vk с хотя бы одним хешем VK-звонка");
        }

        let (host, port) = match peer.rsplit_once(':') {
            Some((host, port)) => (host, port.parse::<u16>()?),
            None => bail!("--peer должен быть в формате host:port, получено {peer}"),
        };
        let local_port = self
            .listen
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .unwrap_or(wdtt_rslib::config::DEFAULT_LOCAL_PORT);

        Ok(WdttLink {
            host: host.to_string(),
            dtls_port: port,
            wg_port: wdtt_rslib::config::DEFAULT_WG_PORT,
            local_port,
            password: password.to_string(),
            hashes: wdtt_rslib::config::parse_hashes(hashes),
        })
    }

    /// Normalizes the worker count the way the reference client does: a
    /// multiple of `WORKERS_PER_GROUP`, clamped to a sane maximum.
    pub fn effective_workers(&self) -> usize {
        const WORKERS_PER_GROUP: usize = 9;
        const MAX_WORKERS: usize = 108;
        let requested = self.workers.clamp(WORKERS_PER_GROUP, MAX_WORKERS);
        (requested / WORKERS_PER_GROUP) * WORKERS_PER_GROUP
    }
}

fn init_logging(level: &str) {
    let filter = match level.to_ascii_lowercase().as_str() {
        "error" => "error",
        "warn" => "warn",
        "debug" => "debug",
        "trace" => "trace",
        _ => "info",
    };
    // Keep the noisy third-party crates quiet unless tracing is requested.
    let directives =
        format!("{filter},webrtc_dtls=warn,webrtc_turn=warn,webrtc_util=warn,boringtun=warn");
    let mut builder = env_logger::Builder::new();
    builder.parse_filters(&directives);
    builder.format_timestamp_millis();
    let _ = builder.try_init();
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    init_logging(&args.log_level);
    if args.events {
        events::set_enabled(true);
    }

    let code = match run(args).await {
        Ok(()) => 0,
        Err(err) => {
            // `{:#}` prints the whole anyhow context chain.
            log::error!("[ФАТАЛ] {err:#}");
            eprintln!("[ФАТАЛ] {err:#}");
            events::emit_error("FATAL", &format!("{err:#}"), true);
            1
        }
    };
    std::process::exit(code);
}

async fn run(args: Args) -> Result<()> {
    let link = args.to_link().context("разбор параметров подключения")?;
    if link.hashes.is_empty() {
        bail!("в ссылке нет ни одного хеша VK-звонка");
    }

    let wrap_key = derive_wrap_key(&link.password).context("вывод WRAP-ключа")?;
    let obfs_mode = ObfsMode::parse(&args.obfs);
    let auth_mode = wdtt_rslib::vk::AuthMode::parse(&args.vk_auth_mode);
    let workers = args.effective_workers();

    let turn_override = match (&args.turn, &args.port) {
        (Some(host), Some(port)) => Some(format!("{host}:{port}")),
        (Some(host), None) => Some(format!("{host}:{}", link.dtls_port)),
        (None, Some(port)) => Some(format!("{}:{port}", link.host)),
        (None, None) => None,
    };

    log::info!("[КЛИЕНТ] ═══════════════════════════════════════");
    log::info!("[КЛИЕНТ] WDTToR v{VERSION}");
    log::info!("[КЛИЕНТ] сервер: {}", link.peer_addr());
    log::info!("[КЛИЕНТ] локальный эндпоинт: {}", link.local_addr());
    log::info!("[КЛИЕНТ] воркеров: {workers}");
    log::info!("[КЛИЕНТ] хешей: {}", link.hashes.len());
    log::info!("[КЛИЕНТ] обфускация: {}", obfs_mode.as_str());
    log::info!("[КЛИЕНТ] VK auth: {}", auth_mode.as_str());
    log::info!("[КЛИЕНТ] устройство: {}", args.device_id);
    log::info!(
        "[КЛИЕНТ] WRAP: включён (HKDF-SHA256 + RTP AEAD), ключ {} байт",
        wrap_key.len()
    );
    log::info!("[КЛИЕНТ] ═══════════════════════════════════════");

    let token = CancellationToken::new();
    install_signal_handler(token.clone());

    events::emit(
        events::EventKind::Started,
        Some(serde_json::json!({
            "version": VERSION,
            "workers": workers,
            "peer": link.peer_addr(),
            "obfs": obfs_mode.as_str(),
        })),
    );

    let stats = Stats::new();
    let dispatcher = Dispatcher::bind(&args.listen, Arc::clone(&stats))
        .await
        .context("запуск локального эндпоинта")?;
    log::info!("[КЛИЕНТ] слушаю {}", dispatcher.local_addr());

    // Statistics loop.
    let stats_task = {
        let stats = Arc::clone(&stats);
        let token = token.clone();
        tokio::spawn(async move { dispatcher::stats_loop(stats, token).await })
    };

    // The first hash drives the credential cache; extra hashes are fallbacks.
    let credentials = CredentialCache::new(link.hashes[0].clone(), auth_mode);
    let ctx = Arc::new(SessionContext {
        link: link.clone(),
        wrap_key: wrap_key.to_vec(),
        obfs_mode,
        device_id: args.device_id.clone(),
        credentials,
        dispatcher: dispatcher.handle(),
        stats: Arc::clone(&stats),
        token: token.clone(),
        turn_override,
        auth_mode,
    });

    // The WireGuard config arrives from the server on the first session.
    let (config_tx, mut config_rx) = mpsc::channel::<String>(1);
    let config_delivered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let config_sink = ConfigSink {
        tx: config_tx,
        delivered: Arc::clone(&config_delivered),
    };

    let pool_task = {
        let ctx = Arc::clone(&ctx);
        let sink = config_sink.clone();
        tokio::spawn(async move { session::run_pool(ctx, workers, Some(sink)).await })
    };

    // Wait for the config, then bring the tunnel up.
    let config = tokio::select! {
        _ = token.cancelled() => None,
        config = tokio::time::timeout(Duration::from_secs(90), config_rx.recv()) => {
            match config {
                Ok(Some(config)) => Some(config),
                Ok(None) => None,
                Err(_) => {
                    log::warn!("[КЛИЕНТ] сервер не выдал конфиг за 90 секунд");
                    None
                }
            }
        }
    };

    let Some(config) = config else {
        token.cancel();
        let _ = pool_task.await;
        let _ = stats_task.await;
        dispatcher.shutdown();
        events::emit_error("NO_CONFIG", "сервер не выдал конфиг WireGuard", true);
        bail!("не удалось получить конфиг WireGuard от сервера");
    };

    let config = wireguard::WgConfig::ensure_mtu(&config);
    log::info!("[КОНФИГ] получен:\n{}", wireguard::redact_config(&config));
    events::emit_config(&config);

    let wg_config = wireguard::parse_config(&config).context("разбор конфига WireGuard")?;
    let tunnel = WgTunnel::new(wg_config.clone()).context("инициализация WireGuard")?;
    log::info!(
        "[WG] локальный адрес {}, MTU {}",
        tunnel.local_v4,
        wg_config.mtu
    );
    // Host applications parse this line to bring up their own interface when
    // the core runs with --no-tun (Android VpnService, iOS, Desktop).
    log::info!("{}", tunnel.tunconf_line());

    stats.mark_connected(now_millis());

    // TUN mode selection.
    let tun_mode = if args.self_test {
        // The self-test talks to the tunnel directly, so no interface is needed.
        TunMode::None
    } else if let Some(addr) = &args.packet_port {
        TunMode::Packet(addr.clone())
    } else if args.no_tun {
        TunMode::None
    } else if let Some(path) = &args.tun_fd_socket {
        TunMode::ExternalFd(path.clone())
    } else {
        TunMode::Own(args.tun_name.clone())
    };

    let mtu = args.mtu.unwrap_or(wg_config.mtu);
    let tun = match &tun_mode {
        TunMode::None | TunMode::Packet(_) => None,
        TunMode::Own(name) => {
            let device = wdtt_rslib::tun::TunDevice::create(name, mtu)
                .with_context(|| format!("создание TUN {name}"))?;
            device
                .configure(tunnel.local_v4, wg_config.prefix_len())
                .with_context(|| format!("настройка TUN {name}"))?;
            log::info!("[TUN] интерфейс {name} поднят, адрес {}", tunnel.local_v4);
            Some(device)
        }
        TunMode::ExternalFd(path) => {
            #[cfg(unix)]
            {
                let fd = wdtt_rslib::tun::receive_fd_from_socket(path)
                    .with_context(|| format!("получение fd из {path}"))?;
                // SAFETY: the fd is owned by us from now on and is a TUN device
                // handed over by the host's VPN service.
                let device = unsafe { wdtt_rslib::tun::TunDevice::from_raw_fd(fd, mtu) }
                    .context("обёртка внешнего TUN fd")?;
                log::info!("[TUN] внешний интерфейс из {path} (fd {fd})");
                Some(device)
            }
            #[cfg(not(unix))]
            {
                bail!("--tun-fd-socket поддерживается только на unix-платформах");
            }
        }
    };

    // Self-test: prove the tunnel carries traffic, without a TUN device.
    if args.self_test {
        return run_self_test(tunnel, dispatcher.local_addr(), token.clone()).await;
    }

    // WireGuard pump: TUN (or host packets) ↔ WireGuard ↔ local endpoint.
    let pump = match tun {
        Some(tun) => {
            let endpoint = dispatcher.local_addr();
            let pump = WgPump::new(tunnel, PumpIo::Tun(tun), endpoint).await?;
            let pump_token = token.clone();
            Some(tokio::spawn(async move { pump.run(pump_token).await }))
        }
        None => {
            if let TunMode::Packet(addr) = &tun_mode {
                // Raw IP packets from the host application (Android VpnService).
                let socket = tokio::net::UdpSocket::bind(addr)
                    .await
                    .with_context(|| format!("пакетный сокет {addr}"))?;
                let local = socket.local_addr().context("адрес пакетного сокета")?;
                log::info!(
                    "[PACKET] сырые IP-пакеты на {local}, WireGuard-эндпоинт {}",
                    dispatcher.local_addr()
                );
                let endpoint = dispatcher.local_addr();
                let pump =
                    WgPump::new(tunnel, PumpIo::Packet { socket, peer: None }, endpoint).await?;
                let pump_token = token.clone();
                Some(tokio::spawn(async move { pump.run(pump_token).await }))
            } else {
                log::info!(
                    "[TUN] режим без интерфейса: WireGuard-эндпоинт {}",
                    dispatcher.local_addr()
                );
                // WireGuard is driven by the host application in this mode, so the
                // best readiness signal we can give is an established worker pool.
                let ready_token = token.clone();
                let ready_stats = Arc::clone(&stats);
                tokio::spawn(async move {
                    wait_for_workers(&ready_token, &ready_stats).await;
                });
                None
            }
        }
    };

    log::info!("[КЛИЕНТ] туннель работает");

    // Wait for shutdown.
    token.cancelled().await;
    log::info!("[КЛИЕНТ] завершение...");

    dispatcher.shutdown();
    if let Some(pump) = pump {
        let _ = tokio::time::timeout(Duration::from_secs(5), pump).await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), pool_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), stats_task).await;

    events::emit(events::EventKind::Stopped, None);
    log::info!("[КЛИЕНТ] остановлен");
    Ok(())
}

/// Where the tunnel packets come from.
enum TunMode {
    /// Create and configure our own interface.
    Own(String),
    /// Receive an fd from the host over a unix socket.
    ExternalFd(String),
    /// No interface: the host runs WireGuard itself.
    None,
    /// No interface: raw IP packets arrive over UDP from the host application.
    Packet(String),
}

/// Pumps packets between the TUN device and the local WireGuard endpoint.
///
/// boringtun encapsulates/decapsulates, and the resulting WireGuard datagrams
/// travel to the dispatcher's UDP socket on loopback — exactly the path the
/// reference client leaves to an external WireGuard implementation, but
/// in-process.
struct WgPump {
    tunnel: WgTunnel,
    /// Where plaintext IP packets come from and go to.
    io: PumpIo,
    /// Socket towards the local endpoint owned by the dispatcher.
    socket: tokio::net::UdpSocket,
}

/// Source and sink of plaintext IP packets.
enum PumpIo {
    /// A real TUN interface.
    Tun(wdtt_rslib::tun::TunDevice),
    /// A UDP socket owned by the host application (Android VpnService, iOS).
    ///
    /// The host sends raw IP packets here and receives them back from the same
    /// address; the core never needs /dev/net/tun, which Android forbids.
    Packet {
        socket: tokio::net::UdpSocket,
        /// Last peer that sent a packet, used as the reply destination.
        peer: Option<std::net::SocketAddr>,
    },
}

impl WgPump {
    async fn new(tunnel: WgTunnel, io: PumpIo, endpoint: std::net::SocketAddr) -> Result<Self> {
        let socket = tokio::net::UdpSocket::bind(if endpoint.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await
        .context("сокет к локальному WireGuard-эндпоинту")?;
        socket
            .connect(endpoint)
            .await
            .with_context(|| format!("подключение к локальному эндпоинту {endpoint}"))?;
        Ok(WgPump { tunnel, io, socket })
    }

    /// Writes one plaintext IP packet back to the host.
    async fn write_packet(&mut self, packet: &[u8]) -> Result<()> {
        match &mut self.io {
            PumpIo::Tun(tun) => tun.write(packet).await.map(|_| ()).context("запись TUN"),
            PumpIo::Packet { socket, peer } => {
                if let Some(addr) = *peer {
                    socket
                        .send_to(packet, addr)
                        .await
                        .context("отправка пакета хосту")?;
                }
                Ok(())
            }
        }
    }

    async fn send(&self, datagram: &[u8]) -> Result<()> {
        self.socket
            .send(datagram)
            .await
            .context("отправка WireGuard-датаграммы")?;
        Ok(())
    }

    async fn run(mut self, token: CancellationToken) {
        let mut tun_buf = vec![0u8; wireguard::MAX_PACKET];
        let mut net_buf = vec![0u8; wireguard::MAX_PACKET];
        let mut timer = tokio::time::interval(Duration::from_millis(250));
        let mut ready = false;

        loop {
            tokio::select! {
                _ = token.cancelled() => return,

                _ = timer.tick() => {
                    for datagram in self.tunnel.update_timers() {
                        if let Err(err) = self.send(&datagram).await {
                            log::debug!("[WG] таймер: {err}");
                        }
                    }
                    // A completed handshake is the real proof that the tunnel
                    // works: sessions may be up while WireGuard is still down.
                    if !ready && self.tunnel.handshake_complete() {
                        ready = true;
                        log::info!("[READY] туннель готов");
                        events::emit_ready();
                    }
                }

                // Outgoing: host packets → WireGuard → local endpoint.
                // The datagram is computed inside the branch so the mutable
                // borrow of `self.io` ends before `self.send()` runs.
                datagram = read_and_encapsulate(&mut self.io, &mut self.tunnel, &mut tun_buf) => {
                    match datagram {
                        Ok(Some(datagram)) => {
                            if let Err(err) = self.send(&datagram).await {
                                log::debug!("[WG] отправка: {err}");
                            }
                        }
                        Ok(None) => {}
                        Err(err) => {
                            log::debug!("[TUN] чтение: {err}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }

                // Incoming: local endpoint → WireGuard → TUN.
                result = self.socket.recv(&mut net_buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            let (plaintext, to_network) = self.tunnel.decapsulate(&net_buf[..n]);
                            for datagram in to_network {
                                if let Err(err) = self.send(&datagram).await {
                                    log::debug!("[WG] ответ пира: {err}");
                                }
                            }
                            if let Some(packet) = plaintext {
                                if let Err(err) = self.write_packet(&packet).await {
                                    log::debug!("[TUN] запись: {err}");
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(err) => {
                            log::debug!("[WG] приём: {err}");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
    }
}

/// Reads one packet from the host side and encapsulates it.
///
/// Kept as a free function so the mutable borrow of the pump's I/O ends before
/// the caller sends the datagram, which needs `&self`.
async fn read_and_encapsulate(
    io: &mut PumpIo,
    tunnel: &mut WgTunnel,
    buf: &mut [u8],
) -> Result<Option<Vec<u8>>> {
    let n = match io {
        PumpIo::Tun(tun) => tun.read(buf).await.context("чтение TUN")?,
        PumpIo::Packet { socket, peer } => {
            let (n, from) = socket
                .recv_from(buf)
                .await
                .context("чтение пакета от хоста")?;
            *peer = Some(from);
            n
        }
    };
    if n == 0 {
        return Ok(None);
    }
    Ok(tunnel.encapsulate(&buf[..n]))
}

/// Waits until the worker pool reports at least one live session, then
/// announces readiness.
///
/// Used in `--no-tun` mode, where the WireGuard pump lives in the host
/// application and this process cannot watch the handshake itself.
async fn wait_for_workers(token: &CancellationToken, stats: &Stats) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = token.cancelled() => return,
            _ = ticker.tick() => {
                if stats.active() > 0 {
                    log::info!("[READY] туннель готов");
                    events::emit_ready();
                    return;
                }
            }
        }
    }
}

/// Sends ICMP echo requests through the tunnel and reports the replies.
///
/// This is the check that matters: a DTLS handshake and a config only prove
/// the control path works. An echo reply proves that WireGuard keys are
/// correct, the server's peer entry is right and packets flow both ways.
async fn run_self_test(
    mut tunnel: WgTunnel,
    endpoint: std::net::SocketAddr,
    token: CancellationToken,
) -> Result<()> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .context("сокет самопроверки")?;
    socket.connect(endpoint).await?;

    let server = wdtt_rslib::probe::server_address(tunnel.local_v4);
    let client = tunnel.local_v4;
    log::info!("[SELFTEST] клиент {client} → сервер {server}");
    log::info!("[SELFTEST] отправляю ICMP echo через туннель...");

    let mut net_buf = vec![0u8; wireguard::MAX_PACKET];
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    let mut ping = tokio::time::interval(Duration::from_secs(1));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut seq: u16 = 0;
    let mut sent = 0u32;
    let mut received = 0u32;
    let mut handshake_seen = false;

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            _ = tokio::time::sleep_until(deadline) => break,

            _ = timer.tick() => {
                for datagram in tunnel.update_timers() {
                    handshake_seen = true;
                    let _ = socket.send(&datagram).await;
                }
            }

            _ = ping.tick() => {
                seq = seq.wrapping_add(1);
                let packet = wdtt_rslib::probe::echo_request(client, server, 0x5744, seq, b"wdtt-selftest");
                sent += 1;
                match tunnel.encapsulate(&packet) {
                    Some(datagram) => {
                        handshake_seen = true;
                        log::info!("[SELFTEST] ping #{seq} отправлен ({} байт WG)", datagram.len());
                        let _ = socket.send(&datagram).await;
                    }
                    None => {
                        // boringtun queues the packet until the handshake completes.
                        log::debug!("[SELFTEST] ping #{seq} отложен: сессия ещё не установлена");
                    }
                }
            }

            result = socket.recv(&mut net_buf) => {
                let Ok(n) = result else { continue };
                if n == 0 { continue; }
                let (plaintext, to_network) = tunnel.decapsulate(&net_buf[..n]);
                for datagram in to_network {
                    let _ = socket.send(&datagram).await;
                }
                if let Some(packet) = plaintext {
                    if let Some(reply_seq) = wdtt_rslib::probe::echo_reply_seq(&packet) {
                        received += 1;
                        log::info!("[SELFTEST] ✓ получен ICMP reply #{reply_seq} ({} байт)", packet.len());
                    }
                }
            }
        }
    }

    if received > 0 {
        log::info!("[SELFTEST] ✓✓ ТУННЕЛЬ РАБОТАЕТ: {received} из {sent} ICMP-ответов через WDTT");
        println!("SELFTEST_OK: {received}/{sent} ICMP replies received");
        Ok(())
    } else if handshake_seen {
        bail!("WireGuard-хендшейк отправлен, но ICMP-ответов нет ({sent} запросов)");
    } else {
        bail!("WireGuard-хендшейк не начался: сессия не установилась");
    }
}

fn install_signal_handler(token: CancellationToken) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(_) => return,
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => log::info!("[КЛИЕНТ] получен SIGINT"),
                _ = sigterm.recv() => log::info!("[КЛИЕНТ] получен SIGTERM"),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            log::info!("[КЛИЕНТ] получен сигнал завершения");
        }
        token.cancel();
    });
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL_LINK: &str = "wdtt://82.40.38.237:56005:56006:9000:uVCF2Nf6dZK8hEKe:sBvxpZXkz_CAoAstXFslhAZmukJ8rI54l8sJDEbQOO4,BRtpXEy74qSrZ-6A6QS5THpi9qoQx7-4JzBRWU4f9Q0,Yb_jusGtRZxh3MFVSmbOqVb6cZm5McRKzrH4YPWE_xM";

    fn parse(argv: &[&str]) -> Args {
        let mut full = vec!["wdtt-rslib"];
        full.extend_from_slice(argv);
        Args::try_parse_from(full).expect("args must parse")
    }

    #[test]
    fn parses_the_real_link_from_the_cli() {
        let args = parse(&["--link", REAL_LINK]);
        let link = args.to_link().unwrap();
        assert_eq!(link.host, "82.40.38.237");
        assert_eq!(link.dtls_port, 56005);
        assert_eq!(link.hashes.len(), 3);
    }

    #[test]
    fn builds_a_link_from_individual_flags() {
        let args = parse(&[
            "--peer",
            "82.40.38.237:56005",
            "--password",
            "uVCF2Nf6dZK8hEKe",
            "--vk",
            "hashone123, hashtwo456",
            "--listen",
            "127.0.0.1:9000",
        ]);
        let link = args.to_link().unwrap();
        assert_eq!(link.host, "82.40.38.237");
        assert_eq!(link.dtls_port, 56005);
        assert_eq!(link.password, "uVCF2Nf6dZK8hEKe");
        assert_eq!(link.hashes, vec!["hashone123", "hashtwo456"]);
        assert_eq!(link.local_port, 9000);
    }

    #[test]
    fn requires_a_password_or_a_link() {
        let args = parse(&["--peer", "1.2.3.4:56000", "--vk", "hashhash1"]);
        assert!(args.to_link().is_err());
    }

    #[test]
    fn requires_hashes() {
        let args = parse(&["--peer", "1.2.3.4:56000", "--password", "p"]);
        assert!(args.to_link().is_err());
    }

    #[test]
    fn worker_count_is_a_multiple_of_nine_and_bounded() {
        assert_eq!(
            parse(&["--link", REAL_LINK, "-n", "9"]).effective_workers(),
            9
        );
        assert_eq!(
            parse(&["--link", REAL_LINK, "-n", "10"]).effective_workers(),
            9
        );
        assert_eq!(
            parse(&["--link", REAL_LINK, "-n", "18"]).effective_workers(),
            18
        );
        // Clamped to the maximum and rounded down.
        assert_eq!(
            parse(&["--link", REAL_LINK, "-n", "500"]).effective_workers(),
            108
        );
        // Below the minimum is raised to one group.
        assert_eq!(
            parse(&["--link", REAL_LINK, "-n", "1"]).effective_workers(),
            9
        );
    }

    #[test]
    fn defaults_match_the_reference_client() {
        let args = parse(&["--link", REAL_LINK]);
        assert_eq!(args.listen, "127.0.0.1:9000");
        assert_eq!(args.obfs, "audio");
        assert_eq!(args.tun_name, "wdtt0");
        assert!(!args.no_tun);
        assert!(args.packet_port.is_none());
        assert!(!args.events);
    }
}
