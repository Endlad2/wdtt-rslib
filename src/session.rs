//! TURN allocation, RTP-obfuscated relay, and DTLS client session.
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::{any::Any, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, sync::mpsc, time::interval};
use webrtc_dtls::{cipher_suite::CipherSuiteId, config::{Config, ExtendedMasterSecretType}, conn::DTLSConn, crypto::Certificate};
use webrtc_turn::client::{Client, ClientConfig};
use webrtc_util::{Conn as DtlsConnTrait, Error as DtlsIoError};
use webrtc_util_legacy::Conn as TurnConn;
use crate::{dispatcher::{Dispatcher, WorkerSlot}, obfs::{obfsUnwrapPacket, obfsWrapPacket, NewObfsConfig, NewObfsState, ObfsConfig, ObfsState}, stats::Stats, worker_group::{Credentials, TurnParams}, wrap::wrapKeyLen};

pub const workerSendBuf: usize = 128;
pub const sessionReadTimeoutSecs: u64 = 1800;
pub const readBufSize: usize = 1600;
pub const socketBufSize: usize = 625 * 1024;
pub const keepaliveByte: u8 = 0xff;
pub const keepaliveIntervalSecs: u64 = 15;

/// Bridges the legacy TURN crate's datagram `Conn` trait into the newer trait
/// used by `webrtc-dtls`, and applies exactly the same packet wrapping as Go.
struct RelayDtlsConn<T: TurnConn + Send + Sync + 'static> {
    relay: Arc<T>, relay_addr: SocketAddr, peer: SocketAddr, key: Option<Vec<u8>>, cfg: Option<ObfsConfig>, state: Option<ObfsState>,
}
impl<T: TurnConn + Send + Sync + 'static> RelayDtlsConn<T> {
    async fn new(relay: Arc<T>, peer: SocketAddr, params: &TurnParams) -> Result<Self> {
        let use_wrap = params.WrapKey.len() == wrapKeyLen;
        let relay_addr = relay.local_addr().await?;
        Ok(Self { relay, relay_addr, peer, key: use_wrap.then(|| params.WrapKey.clone()), cfg: use_wrap.then(|| NewObfsConfig(&params.ObfsMode)), state: use_wrap.then(NewObfsState) })
    }
    fn to_new_error(e: impl std::fmt::Display) -> DtlsIoError { io::Error::new(io::ErrorKind::Other, e.to_string()).into() }
}
#[async_trait]
impl<T: TurnConn + Send + Sync + 'static> DtlsConnTrait for RelayDtlsConn<T> {
    async fn connect(&self, _: SocketAddr) -> std::result::Result<(), DtlsIoError> { Ok(()) }
    async fn recv(&self, dst: &mut [u8]) -> std::result::Result<usize, DtlsIoError> {
        loop { let mut wire = vec![0u8; readBufSize + 80]; let (n, _) = self.relay.recv_from(&mut wire).await.map_err(Self::to_new_error)?; if let Some(key) = &self.key { match obfsUnwrapPacket(key, &wire[..n], dst) { Ok(n) => return Ok(n), Err(_) => continue } } else { if n > dst.len() { return Err(Self::to_new_error("relay packet exceeds buffer")); } dst[..n].copy_from_slice(&wire[..n]); return Ok(n); } }
    }
    async fn recv_from(&self, dst: &mut [u8]) -> std::result::Result<(usize, SocketAddr), DtlsIoError> { let n=self.recv(dst).await?; Ok((n,self.peer)) }
    async fn send(&self, data: &[u8]) -> std::result::Result<usize, DtlsIoError> { let wire=if let (Some(key),Some(cfg),Some(state))=(&self.key,&self.cfg,&self.state){obfsWrapPacket(key,data,cfg,state).map_err(Self::to_new_error)?}else{data.to_vec()}; self.relay.send_to(&wire,self.peer).await.map_err(Self::to_new_error)?; Ok(data.len()) }
    async fn send_to(&self, data: &[u8], _: SocketAddr) -> std::result::Result<usize, DtlsIoError> { self.send(data).await }
    fn local_addr(&self) -> std::result::Result<SocketAddr, DtlsIoError> { Ok(self.relay_addr) }
    fn remote_addr(&self) -> Option<SocketAddr> { Some(self.peer) }
    async fn close(&self) -> std::result::Result<(), DtlsIoError> { Ok(()) }
    fn as_any(&self) -> &(dyn Any + Send + Sync) { self }
}

fn turn_address(params: &TurnParams, creds: &Credentials, session_id: i32) -> Result<String> {
    let url = creds.TurnURLs.get(session_id as usize % creds.TurnURLs.len()).context("нет TURN URL в учетных данных")?;
    let mut addr = url.trim_start_matches("turn:").trim_start_matches("turns:").split('?').next().unwrap_or(url).to_string();
    if !params.Host.is_empty() { let port = if params.Port.is_empty() { addr.rsplit_once(':').map(|x|x.1).unwrap_or("3478") } else { &params.Port }; addr=format!("{}:{port}",params.Host); } else if !params.Port.is_empty() { let host=addr.rsplit_once(':').map(|x|x.0).unwrap_or(&addr); addr=format!("{host}:{}",params.Port); } Ok(addr)
}

pub async fn RunSession(params: &TurnParams, peer: &str, dispatcher: Arc<Dispatcher>, local_port: &str, get_config: bool, config_tx: Option<mpsc::Sender<String>>, session_id: i32, creds: &Credentials, device_id: &str, password: &str, stats: Arc<Stats>) -> Result<bool> {
    let peer: SocketAddr = tokio::net::lookup_host(peer).await?.next().context("резолв peer")?;
    let turn_addr=turn_address(params,creds,session_id)?;
    let socket=UdpSocket::bind(if peer.is_ipv4(){"0.0.0.0:0"}else{"[::]:0"}).await?;
    let turn=Client::new(ClientConfig { stun_serv_addr:turn_addr.clone(), turn_serv_addr:turn_addr.clone(), username:creds.User.clone(), password:creds.Pass.clone(), realm:String::new(), software:String::new(), rto_in_ms:500, conn:Arc::new(socket), vnet:None }).await.context("TURN клиент")?;
    turn.listen().await.context("TURN Listen")?;
    let relay=Arc::new(turn.allocate().await.context("TURN Allocate")?);
    let relay_for_dtls: Arc<dyn DtlsConnTrait + Send + Sync> = Arc::new(RelayDtlsConn::new(relay,peer,params).await?);
    let cert=Certificate::generate_self_signed(vec!["localhost".into()]).context("генерация сертификата")?;
    let dtls=Arc::new(tokio::time::timeout(Duration::from_secs(20),DTLSConn::new(relay_for_dtls,Config { certificates:vec![cert], cipher_suites:vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256], insecure_skip_verify:true, extended_master_secret:ExtendedMasterSecretType::Require, ..Default::default() },true,None)).await.context("DTLS timeout")??);
    let mut config_delivered=false;
    if get_config { let payload=format!("GETCONF:{local_port}|{device_id}|{password}"); dtls.write(payload.as_bytes(),Some(Duration::from_secs(15))).await?; let mut b=[0u8;4096];let n=dtls.read(&mut b,Some(Duration::from_secs(15))).await?; let response=String::from_utf8_lossy(&b[..n]).into_owned(); if response.starts_with("DENIED:"){anyhow::bail!("FATAL_AUTH: {}",response);} if response!="NOCONF" {crate::events::emitConfig(&response); if let Some(tx)=config_tx { let _=tx.send(response).await; } config_delivered=true;} }
    stats.ActiveConnections.fetch_add(1,std::sync::atomic::Ordering::Relaxed); crate::events::emitReady();
    let (tx,mut rx)=mpsc::channel(workerSendBuf); dispatcher.Register(Arc::new(WorkerSlot{ID:session_id,SendCh:tx})).await;
    let mut timer=interval(Duration::from_secs(keepaliveIntervalSecs)); let mut inbound=[0u8;2048];
    loop { tokio::select! { packet=rx.recv()=>match packet { Some(packet)=>{dtls.write(&packet,Some(Duration::from_secs(sessionReadTimeoutSecs))).await?;},None=>break }, result=dtls.read(&mut inbound,Some(Duration::from_secs(sessionReadTimeoutSecs)))=>{let n=result?; if n>0 { dispatcher.ReturnCh.send(inbound[..n].to_vec()).await.map_err(|_|anyhow::anyhow!("dispatcher stopped"))?; }}, _=timer.tick()=>{dtls.write(&[keepaliveByte],Some(Duration::from_secs(5))).await?;} } }
    stats.ActiveConnections.fetch_sub(1,std::sync::atomic::Ordering::Relaxed); dispatcher.Unregister(session_id).await; dtls.close().await?; turn.close().await.context("TURN close")?; Ok(config_delivered)
}
