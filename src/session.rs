use anyhow::{Context, Result};
use async_trait::async_trait;
use std::{any::Any, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, sync::mpsc, time::interval};
use webrtc_dtls::{
    cipher_suite::CipherSuiteId,
    config::{Config, ExtendedMasterSecretType},
    conn::DTLSConn,
    crypto::Certificate,
};
use webrtc_turn::client::{Client, ClientConfig};
use webrtc_util::{Conn as DtlsConnTrait, Error as DtlsIoError};
use webrtc_util_legacy::Conn as TurnConn;

use crate::{
    dispatcher::{Dispatcher, WorkerSlot},
    obfs::{obfsUnwrapPacket, obfsWrapPacket, NewObfsConfig, NewObfsState, ObfsConfig, ObfsState},
    stats::Stats,
    vk_auth::{handleAuthError, isAuthError},
    worker_group::{Credentials, TurnParams},
    wrap::wrapKeyLen,
};

pub const WORKER_SEND_BUF: usize = 128;
pub const SESSION_READ_TIMEOUT_SECS: u64 = 1800;
pub const READ_BUF_SIZE: usize = 1600;
pub const SOCKET_BUF_SIZE: usize = 625 * 1024;
pub const KEEPALIVE_BYTE: u8 = 0xff;
pub const KEEPALIVE_INTERVAL_SECS: u64 = 15;
pub const DTLS_HANDSHAKE_TIMEOUT_SECS: u64 = 60; // Увеличил до 60 секунд

struct RelayDtlsConn<T: TurnConn + Send + Sync + 'static> {
    relay: Arc<T>,
    relay_addr: SocketAddr,
    peer: SocketAddr,
    key: Option<Vec<u8>>,
    cfg: Option<ObfsConfig>,
    state: Option<ObfsState>,
}

impl<T: TurnConn + Send + Sync + 'static> RelayDtlsConn<T> {
    async fn new(relay: Arc<T>, peer: SocketAddr, params: &TurnParams) -> Result<Self> {
        let use_wrap = params.WrapKey.len() == wrapKeyLen;
        eprintln!("[RELAY] WRAP enabled: {}, key len: {}", use_wrap, params.WrapKey.len());
        let relay_addr = relay.local_addr().await?;
        Ok(Self {
            relay,
            relay_addr,
            peer,
            key: use_wrap.then(|| params.WrapKey.clone()),
            cfg: use_wrap.then(|| NewObfsConfig(&params.ObfsMode)),
            state: use_wrap.then(NewObfsState),
        })
    }

    fn to_new_error(e: impl std::fmt::Display) -> DtlsIoError {
        io::Error::new(io::ErrorKind::Other, e.to_string()).into()
    }
}

#[async_trait]
impl<T: TurnConn + Send + Sync + 'static> DtlsConnTrait for RelayDtlsConn<T> {
    async fn connect(&self, _: SocketAddr) -> std::result::Result<(), DtlsIoError> {
        Ok(())
    }

    async fn recv(&self, dst: &mut [u8]) -> std::result::Result<usize, DtlsIoError> {
        loop {
            let mut wire = vec![0u8; READ_BUF_SIZE + 80];
            let (n, _) = self
                .relay
                .recv_from(&mut wire)
                .await
                .map_err(Self::to_new_error)?;
            if let Some(key) = &self.key {
                match obfsUnwrapPacket(key, &wire[..n], dst) {
                    Ok(n) => return Ok(n),
                    Err(_) => continue,
                }
            } else {
                if n > dst.len() {
                    return Err(Self::to_new_error("relay packet exceeds buffer"));
                }
                dst[..n].copy_from_slice(&wire[..n]);
                return Ok(n);
            }
        }
    }

    async fn recv_from(
        &self,
        dst: &mut [u8],
    ) -> std::result::Result<(usize, SocketAddr), DtlsIoError> {
        let n = self.recv(dst).await?;
        Ok((n, self.peer))
    }

    async fn send(&self, data: &[u8]) -> std::result::Result<usize, DtlsIoError> {
        let wire = if let (Some(key), Some(cfg), Some(state)) = (&self.key, &self.cfg, &self.state) {
            obfsWrapPacket(key, data, cfg, state).map_err(Self::to_new_error)?
        } else {
            data.to_vec()
        };
        self.relay
            .send_to(&wire, self.peer)
            .await
            .map_err(Self::to_new_error)?;
        Ok(data.len())
    }

    async fn send_to(
        &self,
        data: &[u8],
        _: SocketAddr,
    ) -> std::result::Result<usize, DtlsIoError> {
        self.send(data).await
    }

    fn local_addr(&self) -> std::result::Result<SocketAddr, DtlsIoError> {
        Ok(self.relay_addr)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.peer)
    }

    async fn close(&self) -> std::result::Result<(), DtlsIoError> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

fn turn_address(params: &TurnParams, creds: &Credentials, session_id: i32) -> Result<String> {
    let url = creds
        .TurnURLs
        .get(session_id as usize % creds.TurnURLs.len())
        .context("нет TURN URL в учетных данных")?;
    let mut addr = url
        .trim_start_matches("turn:")
        .trim_start_matches("turns:")
        .split('?')
        .next()
        .unwrap_or(url)
        .to_string();
    if !params.Host.is_empty() {
        let port = if params.Port.is_empty() {
            addr.rsplit_once(':').map(|x| x.1).unwrap_or("3478")
        } else {
            &params.Port
        };
        addr = format!("{}:{}", params.Host, port);
    } else if !params.Port.is_empty() {
        let host = addr.rsplit_once(':').map(|x| x.0).unwrap_or(&addr);
        addr = format!("{}:{}", host, params.Port);
    }
    Ok(addr)
}

pub async fn RunSession(
    params: &TurnParams,
    peer: &str,
    dispatcher: Arc<Dispatcher>,
    local_port: &str,
    get_config: bool,
    config_tx: Option<mpsc::Sender<String>>,
    session_id: i32,
    creds: &Credentials,
    device_id: &str,
    password: &str,
    stats: Arc<Stats>,
) -> Result<bool> {
    eprintln!("[ВОРКЕР #{}] RunSession started", session_id);
    
    let peer: SocketAddr = tokio::net::lookup_host(peer)
        .await?
        .next()
        .context("резолв peer")?;
    eprintln!("[ВОРКЕР #{}] Peer resolved: {}", session_id, peer);

    let turn_addr = turn_address(params, creds, session_id)?;
    eprintln!("[ВОРКЕР #{}] TURN address: {}", session_id, turn_addr);

    let socket = UdpSocket::bind(if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    eprintln!("[ВОРКЕР #{}] UDP socket bound", session_id);

    eprintln!("[ВОРКЕР #{}] Creating TURN client with user: {} (len: {})", 
        session_id, creds.User, creds.User.len());
    
    let turn = Client::new(ClientConfig {
        stun_serv_addr: turn_addr.clone(),
        turn_serv_addr: turn_addr.clone(),
        username: creds.User.clone(),
        password: creds.Pass.clone(),
        realm: String::new(),
        software: String::new(),
        rto_in_ms: 1000, // Увеличил до 1000ms
        conn: Arc::new(socket),
        vnet: None,
    })
    .await
    .context("TURN клиент")?;
    eprintln!("[ВОРКЕР #{}] TURN client created", session_id);

    turn.listen().await.context("TURN Listen")?;
    eprintln!("[ВОРКЕР #{}] TURN listening", session_id);

    eprintln!("[ВОРКЕР #{}] Allocating TURN...", session_id);
    let relay = match tokio::time::timeout(
        Duration::from_secs(30),
        turn.allocate()
    ).await {
        Ok(Ok(r)) => {
            eprintln!("[ВОРКЕР #{}] TURN allocated successfully!", session_id);
            Arc::new(r)
        }
        Ok(Err(e)) => {
            eprintln!("[ВОРКЕР #{}] TURN allocate error: {}", session_id, e);
            return Err(anyhow::anyhow!("TURN Allocate: {}", e));
        }
        Err(_) => {
            eprintln!("[ВОРКЕР #{}] TURN allocate timeout!", session_id);
            return Err(anyhow::anyhow!("TURN Allocate timeout"));
        }
    };
    eprintln!("[ВОРКЕР #{}] TURN allocated", session_id);

    let relay_for_dtls: Arc<dyn DtlsConnTrait + Send + Sync> =
        Arc::new(RelayDtlsConn::new(relay, peer, params).await?);
    eprintln!("[ВОРКЕР #{}] DTLS relay wrapper created", session_id);

    let cert = Certificate::generate_self_signed(vec!["localhost".into()])
        .context("генерация сертификата")?;
    eprintln!("[ВОРКЕР #{}] Self-signed cert generated", session_id);

    eprintln!("[ВОРКЕР #{}] Starting DTLS handshake...", session_id);
    let dtls = match tokio::time::timeout(
        Duration::from_secs(DTLS_HANDSHAKE_TIMEOUT_SECS),
        DTLSConn::new(
            relay_for_dtls,
            Config {
                certificates: vec![cert],
                cipher_suites: vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
                insecure_skip_verify: true,
                extended_master_secret: ExtendedMasterSecretType::Require,
                ..Default::default()
            },
            true,
            None,
        )
    ).await {
        Ok(Ok(conn)) => {
            eprintln!("[ВОРКЕР #{}] DTLS handshake SUCCESS!", session_id);
            Arc::new(conn)
        }
        Ok(Err(e)) => {
            eprintln!("[ВОРКЕР #{}] DTLS handshake error: {}", session_id, e);
            return Err(anyhow::anyhow!("DTLS handshake error: {}", e));
        }
        Err(_) => {
            eprintln!("[ВОРКЕР #{}] DTLS handshake TIMEOUT ({}s)!", session_id, DTLS_HANDSHAKE_TIMEOUT_SECS);
            return Err(anyhow::anyhow!("DTLS timeout"));
        }
    };

    let mut config_delivered = false;

    if get_config {
        eprintln!("[ВОРКЕР #{}] Requesting config...", session_id);
        let payload = format!("GETCONF:{}|{}|{}", local_port, device_id, password);
        if let Err(e) = dtls
            .write(payload.as_bytes(), Some(Duration::from_secs(15)))
            .await
        {
            let err_msg = e.to_string();
            eprintln!("[ВОРКЕР #{}] Config write error: {}", session_id, err_msg);
            if isAuthError(&anyhow::anyhow!(err_msg.clone())) {
                handleAuthError(creds.CacheStreamID);
                return Err(anyhow::anyhow!("FATAL_AUTH: неверный пароль подключения"));
            }
            return Err(anyhow::anyhow!(e));
        }

        let mut b = [0u8; 4096];
        let n = dtls
            .read(&mut b, Some(Duration::from_secs(15)))
            .await
            .map_err(|e| {
                let err_msg = e.to_string();
                eprintln!("[ВОРКЕР #{}] Config read error: {}", session_id, err_msg);
                if isAuthError(&anyhow::anyhow!(err_msg.clone())) {
                    handleAuthError(creds.CacheStreamID);
                    anyhow::anyhow!("FATAL_AUTH: неверный пароль подключения")
                } else {
                    anyhow::anyhow!(e)
                }
            })?;

        let response = String::from_utf8_lossy(&b[..n]).into_owned();
        eprintln!("[ВОРКЕР #{}] Config response: {}", session_id, response);
        
        if response.starts_with("DENIED:") {
            handleAuthError(creds.CacheStreamID);
            anyhow::bail!("FATAL_AUTH: {}", response);
        }
        if response != "NOCONF" {
            crate::events::emitConfig(&response);
            if let Some(tx) = config_tx {
                let _ = tx.send(response).await;
            }
            config_delivered = true;
            eprintln!("[ВОРКЕР #{}] Config delivered!", session_id);
        }
    }

    stats.ActiveConnections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    crate::events::emitReady();
    eprintln!("[ВОРКЕР #{}] Session ready!", session_id);

    let (tx, mut rx) = mpsc::channel(WORKER_SEND_BUF);
    dispatcher
        .Register(Arc::new(WorkerSlot {
            ID: session_id,
            SendCh: tx,
        }))
        .await;

    let mut timer = interval(Duration::from_secs(KEEPALIVE_INTERVAL_SECS));
    let mut inbound = [0u8; 2048];

    loop {
        tokio::select! {
            packet = rx.recv() => {
                match packet {
                    Some(packet) => {
                        if let Err(e) = dtls.write(&packet, Some(Duration::from_secs(SESSION_READ_TIMEOUT_SECS))).await {
                            let err_msg = e.to_string();
                            eprintln!("[ВОРКЕР #{}] Write error: {}", session_id, err_msg);
                            if isAuthError(&anyhow::anyhow!(err_msg)) {
                                handleAuthError(creds.CacheStreamID);
                            }
                            break;
                        }
                    }
                    None => break,
                }
            }
            result = dtls.read(&mut inbound, Some(Duration::from_secs(SESSION_READ_TIMEOUT_SECS))) => {
                match result {
                    Ok(n) => {
                        if n > 0 {
                            if let Err(e) = dispatcher.ReturnCh.send(inbound[..n].to_vec()).await {
                                eprintln!("[SESSION #{}] dispatcher stopped: {}", session_id, e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        let err_msg = e.to_string();
                        eprintln!("[ВОРКЕР #{}] Read error: {}", session_id, err_msg);
                        if isAuthError(&anyhow::anyhow!(err_msg)) {
                            handleAuthError(creds.CacheStreamID);
                        }
                        break;
                    }
                }
            }
            _ = timer.tick() => {
                if let Err(e) = dtls.write(&[KEEPALIVE_BYTE], Some(Duration::from_secs(5))).await {
                    let err_msg = e.to_string();
                    eprintln!("[ВОРКЕР #{}] Keepalive error: {}", session_id, err_msg);
                    if isAuthError(&anyhow::anyhow!(err_msg)) {
                        handleAuthError(creds.CacheStreamID);
                    }
                    break;
                }
            }
        }
    }

    stats.ActiveConnections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    dispatcher.Unregister(session_id).await;
    let _ = dtls.close().await;
    let _ = turn.close().await.context("TURN close");
    eprintln!("[ВОРКЕР #{}] Session closed", session_id);

    Ok(config_delivered)
}