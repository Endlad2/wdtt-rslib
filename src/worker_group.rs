use std::{collections::HashSet,sync::{Arc,atomic::{AtomicBool,Ordering}},time::Duration};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use crate::{dispatcher::Dispatcher,session::RunSession,stats::Stats,vk_auth::GetCreds};

pub const workersPerGroup: usize = 9;
pub const defaultCycleSecs: u64 = 36000;

#[derive(Clone, Debug)] pub struct TurnParams { pub Host:String, pub Port:String, pub Hashes:Vec<String>, pub WrapKey:Vec<u8>, pub ObfsMode:String }
#[derive(Clone, Debug)] pub struct Credentials { pub User:String, pub Pass:String, pub TurnURLs:Vec<String>, pub CacheStreamID:i32 }

pub fn normalizeVKJoinHash(input:&str)->String { let mut s=input.trim().trim_matches(|c|matches!(c,'<'|'>'|'\"'|'\'')).to_string(); if s.is_empty(){return s}; let l=s.to_lowercase(); if let Some(i)=l.find("/call/join/"){s=s[i+11..].into()}else if l.starts_with("http://")||l.starts_with("https://"){return String::new()} if let Some(i)=s.find(|c|matches!(c,'?'|'#'|'/')){s.truncate(i)} s.trim().trim_matches('/').into() }
pub fn ParseHashes(raw:&str)->Vec<String>{ let mut seen=HashSet::new(); raw.split(|c:char|matches!(c,','|';'|'\n'|'\r'|'\t'|' ')).filter_map(|h|{let h=normalizeVKJoinHash(h);if !h.is_empty()&&seen.insert(h.clone()){Some(h)}else{None}}).collect() }

#[allow(clippy::too_many_arguments)]
pub async fn WorkerGroup(cancel: CancellationToken, group_id: i32, hash_index: usize, params: Arc<TurnParams>, peer: String, dispatcher: Arc<Dispatcher>, local_port: String, get_config: bool, config_tx: mpsc::Sender<String>, worker_ids: Vec<i32>, paused: Arc<AtomicBool>, device_id: String, password: String, stats: Arc<Stats>) {
    while paused.load(Ordering::Relaxed) { tokio::select! { _=cancel.cancelled()=>return, _=tokio::time::sleep(Duration::from_secs(1))=>{} } }
    let Some(hash)=params.Hashes.get(hash_index%params.Hashes.len()).cloned() else{return};
    let stream_id=group_id*100;
    let credentials=match GetCreds(&hash,stream_id).await { Ok((user,pass,urls))=>Credentials{User:user,Pass:pass,TurnURLs:urls,CacheStreamID:stream_id}, Err(e)=>{eprintln!("[ГРУППА #{group_id}] Ошибка кредов: {e}");return} };
    let config_once=Arc::new(AtomicBool::new(get_config));
    let mut handles=Vec::with_capacity(worker_ids.len());
    for worker_id in worker_ids { let cancel=cancel.clone();let params=params.clone();let peer=peer.clone();let dispatcher=dispatcher.clone();let port=local_port.clone();let device_id=device_id.clone();let password=password.clone();let credentials=credentials.clone();let tx=config_tx.clone();let config_once=config_once.clone();let paused=paused.clone();let stats=stats.clone();handles.push(tokio::spawn(async move { loop { if cancel.is_cancelled(){return} while paused.load(Ordering::Relaxed){tokio::select!{_=cancel.cancelled()=>return,_=tokio::time::sleep(Duration::from_secs(1))=>{}}} let want_config=config_once.swap(false,Ordering::AcqRel); let result=RunSession(&params,&peer,dispatcher.clone(),&port,want_config,if want_config{Some(tx.clone())}else{None},worker_id,&credentials,&device_id,&password,stats.clone()).await; match result { Ok(_)=>{},Err(e)=>{eprintln!("[ВОРКЕР #{worker_id}] Сессия: {e}"); if e.to_string().contains("FATAL_AUTH"){cancel.cancel();return;} } } tokio::select!{_=cancel.cancelled()=>return,_=tokio::time::sleep(Duration::from_secs(2))=>{}} } })); }
    for h in handles { let _=h.await; }
}
