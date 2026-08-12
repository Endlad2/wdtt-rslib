use anyhow::{anyhow, Result};
use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex, RwLock},
    time::{Duration, Instant},
};
use crate::creds_vkcalls::getVKCredsViaVKCallsPath;

#[derive(Clone, Debug)]
pub struct VKCredentials {
    pub ClientID: String,
    pub ClientSecret: String,
}

pub fn deobf(s: &str, shift: i8) -> String {
    s.bytes()
        .map(|b| (b as i16 + shift as i16) as u8 as char)
        .collect()
}

pub fn parseVKCredentialsEnv(env: &str) -> Result<Vec<VKCredentials>> {
    let v: Vec<_> = env
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|x| {
            let (a, b) = x
                .trim()
                .split_once(':')
                .ok_or_else(|| anyhow!("invalid credential pair"))?;
            if a.is_empty() || b.is_empty() {
                return Err(anyhow!("empty credential"));
            }
            Ok(VKCredentials {
                ClientID: a.into(),
                ClientSecret: b.into(),
            })
        })
        .collect::<Result<_>>()?;
    if v.is_empty() {
        return Err(anyhow!("no credentials found"));
    }
    Ok(v)
}

pub fn loadVKCredentials() -> Vec<VKCredentials> {
    std::env::var("WDTT_VK_CREDENTIALS")
        .ok()
        .and_then(|x| parseVKCredentialsEnv(&x).ok())
        .unwrap_or_else(|| {
            vec![VKCredentials {
                ClientID: deobf(";535939", -3),
                ClientSecret: deobf("oPUvWlPF|Sqs8yirogpq", -3),
            }]
        })
}

static VK_CREDENTIALS_LIST: LazyLock<RwLock<Vec<VKCredentials>>> =
    LazyLock::new(|| RwLock::new(loadVKCredentials()));

pub fn SetActiveClientIds(ids: &str) {
    let known: HashMap<&str, (&str, &str)> = [
        ("6287487", ("6287487", "MuAxFaKDYDOICzGnEOhp")),
        ("8202606", ("8202606", "lMRsTiMCyPnp5vfoldmn")),
    ]
    .into();
    let v: Vec<_> = ids
        .split(',')
        .filter_map(|i| {
            known
                .get(i.trim())
                .map(|(a, b)| VKCredentials {
                    ClientID: (*a).into(),
                    ClientSecret: (*b).into(),
                })
        })
        .collect();
    if !v.is_empty() {
        *VK_CREDENTIALS_LIST.write().unwrap() = v;
    }
}

pub fn GetActiveClientIdsString() -> String {
    VK_CREDENTIALS_LIST
        .read()
        .unwrap()
        .iter()
        .map(|c| c.ClientID.clone())
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug)]
pub struct CallUnavailableError {
    pub Code: i64,
    pub Message: String,
}

impl std::fmt::Display for CallUnavailableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VK call is unavailable: {} (error_code={})",
            self.Message, self.Code
        )
    }
}

impl std::error::Error for CallUnavailableError {}

pub fn asCallUnavailableError(_: &anyhow::Error) -> Option<&CallUnavailableError> {
    None
}

pub fn fatalCallError(v: &serde_json::Value) -> Option<CallUnavailableError> {
    let err_obj = v.get("error")?;
    let obj = err_obj.as_object()?;

    let code = obj
        .get("error_code")
        .and_then(|c| c.as_f64())
        .unwrap_or(0.0) as i64;

    let is_fatal = code == 951 || code == 954 || (9000..=9999).contains(&code);

    if !is_fatal {
        return None;
    }

    let msg = obj
        .get("error_msg")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();

    Some(CallUnavailableError {
        Code: code,
        Message: msg,
    })
}

pub fn vkErrorCode(v: &serde_json::Value) -> i64 {
    v.as_i64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0)
}

#[derive(Clone)]
pub struct TurnCredentials {
    pub Username: String,
    pub Password: String,
    pub ServerAddrs: Vec<String>,
    pub ExpiresAt: Instant,
    pub Link: String,
}

pub struct StreamCredentialsCache {
    pub creds: Option<TurnCredentials>,
}

static CACHES: LazyLock<Mutex<HashMap<i32, StreamCredentialsCache>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub const STREAMS_PER_CACHE: i32 = 10;

pub fn getCacheID(streamID: i32) -> i32 {
    streamID / STREAMS_PER_CACHE
}

pub fn getStreamCache(_: i32) {}

pub fn cloneStringSlice(v: &[String]) -> Vec<String> {
    v.to_vec()
}

pub fn isAuthError(err: &anyhow::Error) -> bool {
    let s = err.to_string();
    ["401", "Unauthorized", "authentication", "invalid credential", "stale nonce"]
        .iter()
        .any(|x| s.contains(x))
}

pub fn handleAuthError(streamID: i32) -> bool {
    let key = getCacheID(streamID);
    CACHES.lock().unwrap().remove(&key);
    true
}

pub async fn getVkCredsCached(link: &str, streamID: i32) -> Result<(String, String, Vec<String>)> {
    let key = getCacheID(streamID);

    if let Some(c) = CACHES
        .lock()
        .unwrap()
        .get(&key)
        .and_then(|x| x.creds.clone())
        .filter(|c| c.Link == link && c.ExpiresAt > Instant::now())
    {
        return Ok((c.Username, c.Password, c.ServerAddrs));
    }

    let (u, p, a) = fetchVkCredsSerialized(link, streamID).await?;

    CACHES.lock().unwrap().insert(
        key,
        StreamCredentialsCache {
            creds: Some(TurnCredentials {
                Username: u.clone(),
                Password: p.clone(),
                ServerAddrs: a.clone(),
                ExpiresAt: Instant::now() + Duration::from_secs(540),
                Link: link.into(),
            }),
        },
    );

    Ok((u, p, a))
}

pub async fn fetchVkCredsSerialized(link: &str, streamID: i32) -> Result<(String, String, Vec<String>)> {
    fetchVkCreds(link, streamID).await
}

pub async fn fetchVkCreds(link: &str, streamID: i32) -> Result<(String, String, Vec<String>)> {
    getVKCredsViaVKCallsPath(link, streamID).await
}

pub async fn getTokenChain(
    _: &str,
    _: i32,
    _: VKCredentials,
) -> Result<(String, String, Vec<String>)> {
    Err(anyhow!("legacy VK auth is not yet available; use vkcalls"))
}

pub async fn GetCreds(link: &str, streamID: i32) -> Result<(String, String, Vec<String>)> {
    getVkCredsCached(link, streamID).await
}