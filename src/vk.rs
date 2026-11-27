// SPDX-License-Identifier: LGPL-2.1
//
//! VK call join hashes → TURN credentials.
//!
//! The WDTT server does not know the TURN credentials: they are issued by VK
//! for a specific call. This module reproduces the reference client's "legacy"
//! token chain, which is the one VK still serves without a browser:
//!
//! 1. `login.vk.ru/?act=get_anonym_token` → anonymous access token;
//! 2. `api.vk.ru/method/calls.getCallPreview` → validates the join link;
//! 3. `api.vk.ru/method/calls.getAnonymousToken` → OK CDN anonym token;
//! 4. `calls.okcdn.ru/fb.do method=auth.anonymLogin` → session key;
//! 5. `calls.okcdn.ru/fb.do method=vchat.joinConversationByLink` →
//!    `turn_server.username` / `turn_server.credential` / `turn_server.urls`.
//!
//! Requests carry a full browser header set (UA, Sec-CH-UA, Sec-Fetch-*)
//! because VK rejects obviously non-browser clients.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use serde_json::Value;
use url::Url;
use uuid::Uuid;

/// VK application credentials used by the reference client. They are public
/// (shipped in the original app) and only used to obtain anonymous tokens.
const VK_APP_CREDENTIALS: [(&str, &str); 2] = [
    ("8202606", "lMRsTiMCyPnp5vfoldmn"),
    ("6287487", "MuAxFaKDYDOICzGnEOhp"),
];

const VK_API_VERSION: &str = "5.275";
const OK_APP_KEY: &str = "CGMMEJLGDIHBABABA";

const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";

/// TURN credentials issued by VK for one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnCredentials {
    pub username: String,
    pub password: String,
    /// TURN server addresses in `host:port` form.
    pub urls: Vec<String>,
}

/// Errors that must stop the retry loop (bad hash, banned app, captcha wall).
#[derive(Debug)]
pub enum VkError {
    /// The call is gone or unavailable: retrying with the same hash is futile.
    CallUnavailable(String),
    /// The credentials/app were rejected.
    Fatal(String),
    /// Anything worth retrying later.
    Retryable(String),
}

impl std::fmt::Display for VkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VkError::CallUnavailable(m) => write!(f, "звонок недоступен: {m}"),
            VkError::Fatal(m) => write!(f, "фатальная ошибка VK: {m}"),
            VkError::Retryable(m) => write!(f, "ошибка VK: {m}"),
        }
    }
}

impl std::error::Error for VkError {}

/// Builds a client with browser-shaped headers.
fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent(USER_AGENT)
        .gzip(true)
        .brotli(true)
        .build()
        .context("building the VK HTTP client")
}

fn browser_headers(request: reqwest::RequestBuilder, origin: &str) -> reqwest::RequestBuilder {
    request
        .header("Accept", "*/*")
        .header("Accept-Language", "en-GB,en;q=0.9")
        .header(
            "Sec-CH-UA",
            "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"146\"",
        )
        .header("Sec-CH-UA-Mobile", "?0")
        .header("Sec-CH-UA-Platform", "\"Windows\"")
        .header("Origin", origin)
        .header("Referer", &format!("{origin}/"))
        .header("Sec-Fetch-Site", "same-site")
        .header("Sec-Fetch-Mode", "cors")
        .header("Sec-Fetch-Dest", "empty")
        .header("Priority", "u=1, i")
}

/// POSTs form data and parses a JSON object.
async fn post_form(
    client: &reqwest::Client,
    url: &str,
    form: &[(&str, String)],
    origin: &str,
) -> Result<Value> {
    let response = browser_headers(client.post(url), origin)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(form)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;

    let status = response.status();
    let body = response.text().await.context("reading the VK response")?;
    if !status.is_success() {
        bail!("POST {url} → HTTP {status}: {:.200}", body);
    }
    serde_json::from_str(&body).with_context(|| format!("parsing JSON from {url}: {:.200}", body))
}

fn random_delay(min_ms: u64, max_ms: u64) {
    let ms = rand::thread_rng().gen_range(min_ms..=max_ms.max(min_ms));
    std::thread::sleep(Duration::from_millis(ms));
}

fn random_name() -> String {
    const FIRST: [&str; 12] = [
        "Иван",
        "Алексей",
        "Михаил",
        "Андрей",
        "Сергей",
        "Дмитрий",
        "Павел",
        "Никита",
        "Мария",
        "Анна",
        "Елена",
        "Ольга",
    ];
    let mut rng = rand::thread_rng();
    let first = FIRST[rng.gen_range(0..FIRST.len())];
    let suffix = rng.gen_range(10..99);
    format!("{first}{suffix}")
}

/// Extracts a string at a JSON path.
fn json_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

/// Detects VK errors that mean "stop retrying this hash".
fn classify_vk_error(error: &Value) -> Option<VkError> {
    let code = error.get("error_code").and_then(|v| v.as_i64());
    let message = error
        .get("error_msg")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let code = code?;
    // 9000-9999 and 951/954 are call lifecycle errors: the link is dead.
    if (9000..=9999).contains(&code) || code == 951 || code == 954 {
        return Some(VkError::CallUnavailable(format!(
            "{message} (error_code={code})"
        )));
    }
    Some(VkError::Retryable(format!("{message} (error_code={code})")))
}

/// Auth strategy, mirroring the reference client's `--vk-auth-mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// `messages.getAnonymCallToken` chain on `api.vk.me`. This is the default
    /// in the reference client because it usually avoids the captcha gate.
    VkCalls,
    /// The `calls.*` chain on `api.vk.ru`. Older, more likely to hit captcha.
    Legacy,
}

impl AuthMode {
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "legacy" => AuthMode::Legacy,
            _ => AuthMode::VkCalls,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AuthMode::VkCalls => "vkcalls",
            AuthMode::Legacy => "legacy",
        }
    }
}

/// VK Connect client id used by the `vkcalls` chain.
const VK_CONNECT_CLIENT_ID: &str = "8093730";
const VK_CALLS_HOST: &str = "api.vk.me";
const VK_CALLS_API_VERSION: &str = "5.276";

/// Fetches TURN credentials using the requested strategy.
///
/// `vkcalls` is tried first when selected; any non-fatal failure falls back to
/// the legacy chain, exactly like the reference implementation.
pub async fn fetch_turn_credentials_mode(
    hash: &str,
    mode: AuthMode,
) -> Result<TurnCredentials, VkError> {
    if mode == AuthMode::VkCalls {
        match fetch_via_vkcalls(hash).await {
            Ok(creds) => return Ok(creds),
            Err(err) => {
                if matches!(err, VkError::CallUnavailable(_)) {
                    return Err(err);
                }
                log::info!("[VK] путь vkcalls не сработал ({err}), пробую legacy");
            }
        }
    }
    fetch_turn_credentials(hash).await
}

/// The `vkcalls` chain: api.vk.me + OK CDN, no browser required.
async fn fetch_via_vkcalls(hash: &str) -> Result<TurnCredentials, VkError> {
    let client = client().map_err(|e| VkError::Retryable(e.to_string()))?;
    let device_id = Uuid::new_v4().to_string();
    let name = random_name();
    let join_link = format!("https://vk.com/call/join/{hash}");

    // Step 1: anonymous token for the call.
    let url1 = format!(
        "https://{VK_CALLS_HOST}/method/auth.getAnonymToken?v={VK_CALLS_API_VERSION}\
&client_id={VK_CONNECT_CLIENT_ID}&link={}&device_id={device_id}&anonymName={}&lang=en",
        urlencoding(&join_link),
        urlencoding(&name)
    );
    let resp1 = post_json(&client, &url1, "https://vk.com").await?;
    check_vk_error(&resp1)?;
    let anonym_token = json_str(&resp1, &["response", "token"])
        .map(str::to_string)
        .ok_or_else(|| VkError::Retryable(format!("auth.getAnonymToken: нет токена в {resp1}")))?;

    // Step 2: call preview → user_id + secret.
    let url2 = format!(
        "https://{VK_CALLS_HOST}/method/messages.getCallPreview?v={VK_CALLS_API_VERSION}\
&anonymous_token={}&device_id={device_id}&extended=1\
&fields=first_name,last_name,photo_200&lang=en&link={}",
        urlencoding(&anonym_token),
        urlencoding(&join_link)
    );
    let resp2 = post_json(&client, &url2, "https://vk.com").await?;
    check_vk_error(&resp2)?;
    let user_id = resp2
        .get("response")
        .and_then(|r| r.get("user_id"))
        .and_then(|v| v.as_f64())
        .ok_or_else(|| VkError::Retryable(format!("getCallPreview: нет user_id в {resp2}")))?;
    let secret = json_str(&resp2, &["response", "secret"])
        .ok_or_else(|| VkError::Retryable(format!("getCallPreview: нет secret в {resp2}")))?
        .to_string();

    // Step 3: OK CDN anonym token.
    let url3 = format!(
        "https://{VK_CALLS_HOST}/method/messages.getAnonymCallToken?v={VK_CALLS_API_VERSION}\
&anonymous_token={}&device_id={device_id}&link={}&name={}&user_id={}\
&secret={}&lang=en",
        urlencoding(&anonym_token),
        urlencoding(&join_link),
        urlencoding(&name),
        user_id as i64,
        urlencoding(&secret)
    );
    let resp3 = post_json(&client, &url3, "https://vk.com").await?;
    check_vk_error(&resp3)?;
    let ok_token = json_str(&resp3, &["response", "token"])
        .ok_or_else(|| VkError::Retryable(format!("getAnonymCallToken: нет токена в {resp3}")))?
        .to_string();

    // Step 4: OK CDN session.
    let session_data = format!(
        r#"{{"version":2,"device_id":"{}","client_version":"1.0.1"}}"#,
        Uuid::new_v4()
    );
    let url4 = format!(
        "https://calls.okcdn.ru/fb.do?session_data={}&method=auth.anonymLogin\
&format=JSON&application_key={OK_APP_KEY}",
        urlencoding(&session_data)
    );
    let resp4 = post_json(&client, &url4, "https://calls.okcdn.ru").await?;
    let session_key = json_str(&resp4, &["session_key"])
        .ok_or_else(|| VkError::Retryable(format!("anonymLogin: нет session_key в {resp4}")))?
        .to_string();

    // Step 5: join and read the TURN block.
    let url5 = format!(
        "https://calls.okcdn.ru/fb.do?joinLink={hash}&isVideo=false&protocolVersion=5\
&anonymToken={}&method=vchat.joinConversationByLink&format=JSON\
&application_key={OK_APP_KEY}&session_key={}",
        urlencoding(&ok_token),
        urlencoding(&session_key)
    );
    let resp5 = post_json(&client, &url5, "https://calls.okcdn.ru").await?;
    if let Some(code) = resp5.get("error_code").and_then(|v| v.as_i64()) {
        if code != 0 {
            let message = resp5
                .get("error_msg")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            return Err(VkError::Retryable(format!(
                "joinConversationByLink: {message} (error_code={code})"
            )));
        }
    }

    let username = json_str(&resp5, &["turn_server", "username"])
        .ok_or_else(|| VkError::Retryable(format!("vkcalls: нет turn_server.username в {resp5}")))?
        .to_string();
    let password = json_str(&resp5, &["turn_server", "credential"])
        .ok_or_else(|| {
            VkError::Retryable(format!("vkcalls: нет turn_server.credential в {resp5}"))
        })?
        .to_string();
    let urls: Vec<String> = resp5
        .get("turn_server")
        .and_then(|t| t.get("urls"))
        .and_then(|u| u.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|u| u.as_str())
                .filter_map(|u| crate::turn::normalize_turn_url(u).ok())
                .collect()
        })
        .unwrap_or_default();

    if urls.is_empty() {
        return Err(VkError::Retryable(
            "vkcalls: VK вернул пустой список TURN-серверов".to_string(),
        ));
    }

    log::info!("[VK] vkcalls: получены креды (urls={})", urls.len());
    Ok(TurnCredentials {
        username,
        password,
        urls,
    })
}

/// Percent-encodes a query parameter the way `net/url.QueryEscape` does.
fn urlencoding(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// GETs a JSON document with browser headers.
async fn post_json(client: &reqwest::Client, url: &str, origin: &str) -> Result<Value, VkError> {
    let response = browser_headers(client.get(url), origin)
        .send()
        .await
        .map_err(|e| VkError::Retryable(format!("GET {url}: {e}")))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| VkError::Retryable(format!("чтение ответа {url}: {e}")))?;
    if !status.is_success() {
        return Err(VkError::Retryable(format!(
            "GET {url} → HTTP {status}: {:.200}",
            body
        )));
    }
    serde_json::from_str(&body)
        .map_err(|e| VkError::Retryable(format!("разбор JSON из {url}: {e}: {:.200}", body)))
}

/// Fails when the response carries a VK API error.
fn check_vk_error(response: &Value) -> Result<(), VkError> {
    match response.get("error") {
        None => Ok(()),
        Some(error) => {
            let code = error.get("error_code").and_then(|v| v.as_i64());
            if code == Some(14) {
                return Err(VkError::Fatal(
                    "VK требует капчу: решите её в браузере и повторите".to_string(),
                ));
            }
            Err(classify_vk_error(error)
                .unwrap_or_else(|| VkError::Retryable("VK API error".to_string())))
        }
    }
}

/// Fetches TURN credentials for one VK call join hash.
///
/// Tries the shipped application credentials in order; a `Fatal` or
/// `CallUnavailable` result stops immediately.
pub async fn fetch_turn_credentials(hash: &str) -> Result<TurnCredentials, VkError> {
    let client = client().map_err(|e| VkError::Retryable(e.to_string()))?;
    let mut last: Option<VkError> = None;

    for (client_id, client_secret) in VK_APP_CREDENTIALS {
        match fetch_with_credentials(&client, hash, client_id, client_secret).await {
            Ok(creds) => return Ok(creds),
            Err(err) => {
                let fatal = matches!(err, VkError::CallUnavailable(_) | VkError::Fatal(_));
                last = Some(err);
                if fatal {
                    break;
                }
            }
        }
    }

    Err(last.unwrap_or_else(|| VkError::Retryable("no VK credentials configured".to_string())))
}

async fn fetch_with_credentials(
    client: &reqwest::Client,
    hash: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<TurnCredentials, VkError> {
    let name = random_name();
    let join_link = format!("https://vk.com/call/join/{hash}");

    // Step 1: anonymous access token.
    let token1 = post_form(
        client,
        "https://login.vk.ru/?act=get_anonym_token",
        &[
            ("client_id", client_id.to_string()),
            ("token_type", "messages".to_string()),
            ("client_secret", client_secret.to_string()),
            ("version", "1".to_string()),
            ("app_id", client_id.to_string()),
        ],
        "https://vk.ru",
    )
    .await
    .map_err(|e| VkError::Retryable(format!("get_anonym_token: {e}")))?;

    if let Some(error) = token1.get("error") {
        return Err(classify_vk_error(error)
            .unwrap_or_else(|| VkError::Retryable("get_anonym_token failed".to_string())));
    }
    let token1 = json_str(&token1, &["data", "access_token"])
        .ok_or_else(|| VkError::Retryable(format!("no access_token in {token1}")))?
        .to_string();

    random_delay(100, 150);

    // Step 2: call preview. Errors here are not fatal by themselves.
    let preview_url = format!(
        "https://api.vk.ru/method/calls.getCallPreview?v={VK_API_VERSION}&client_id={client_id}"
    );
    match post_form(
        client,
        &preview_url,
        &[
            ("vk_join_link", join_link.clone()),
            ("fields", "photo_200".to_string()),
            ("access_token", token1.clone()),
        ],
        "https://vk.ru",
    )
    .await
    {
        Ok(preview) => {
            if let Some(error) = preview.get("error") {
                if let Some(VkError::CallUnavailable(message)) = classify_vk_error(error) {
                    return Err(VkError::CallUnavailable(message));
                }
            }
        }
        Err(err) => log::debug!("[VK] getCallPreview failed (continuing): {err}"),
    }

    random_delay(200, 400);

    // Step 3: OK CDN anonym token.
    let anon_url = format!(
        "https://api.vk.ru/method/calls.getAnonymousToken?v={VK_API_VERSION}&client_id={client_id}"
    );
    let anon = post_form(
        client,
        &anon_url,
        &[
            ("vk_join_link", join_link),
            ("name", name.clone()),
            ("access_token", token1),
        ],
        "https://vk.ru",
    )
    .await
    .map_err(|e| VkError::Retryable(format!("getAnonymousToken: {e}")))?;

    if let Some(error) = anon.get("error") {
        if error.get("error_code").and_then(|v| v.as_i64()) == Some(14) {
            return Err(VkError::Fatal(
                "VK требует капчу: решите её в браузере и повторите".to_string(),
            ));
        }
        return Err(classify_vk_error(error)
            .unwrap_or_else(|| VkError::Retryable("getAnonymousToken failed".to_string())));
    }
    let ok_token = json_str(&anon, &["response", "token"])
        .ok_or_else(|| VkError::Retryable(format!("no token in {anon}")))?
        .to_string();

    random_delay(100, 150);

    // Step 4: OK CDN session.
    let session_data = format!(
        r#"{{"version":2,"device_id":"{}","client_version":1.1,"client_type":"SDK_JS"}}"#,
        Uuid::new_v4()
    );
    let session = post_form(
        client,
        "https://calls.okcdn.ru/fb.do",
        &[
            ("session_data", session_data),
            ("method", "auth.anonymLogin".to_string()),
            ("format", "JSON".to_string()),
            ("application_key", OK_APP_KEY.to_string()),
        ],
        "https://calls.okcdn.ru",
    )
    .await
    .map_err(|e| VkError::Retryable(format!("anonymLogin: {e}")))?;
    let session_key = json_str(&session, &["session_key"])
        .ok_or_else(|| VkError::Retryable(format!("no session_key in {session}")))?
        .to_string();

    random_delay(100, 150);

    // Step 5: join the conversation and take the TURN server block.
    let joined = post_form(
        client,
        "https://calls.okcdn.ru/fb.do",
        &[
            ("joinLink", hash.to_string()),
            ("isVideo", "false".to_string()),
            ("protocolVersion", "5".to_string()),
            ("capabilities", "2F7F".to_string()),
            ("anonymToken", ok_token),
            ("method", "vchat.joinConversationByLink".to_string()),
            ("format", "JSON".to_string()),
            ("application_key", OK_APP_KEY.to_string()),
            ("session_key", session_key),
        ],
        "https://calls.okcdn.ru",
    )
    .await
    .map_err(|e| VkError::Retryable(format!("joinConversationByLink: {e}")))?;

    if let Some(code) = joined.get("error_code").and_then(|v| v.as_i64()) {
        if code != 0 {
            let message = joined
                .get("error_msg")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            return Err(VkError::Retryable(format!(
                "joinConversationByLink: {message} (error_code={code})"
            )));
        }
    }

    let username = json_str(&joined, &["turn_server", "username"])
        .ok_or_else(|| VkError::Retryable(format!("no turn_server.username in {joined}")))?
        .to_string();
    let password = json_str(&joined, &["turn_server", "credential"])
        .ok_or_else(|| VkError::Retryable(format!("no turn_server.credential in {joined}")))?
        .to_string();

    let raw_urls = joined
        .get("turn_server")
        .and_then(|t| t.get("urls"))
        .and_then(|u| u.as_array())
        .ok_or_else(|| VkError::Retryable("turn_server.urls is missing".to_string()))?;

    let urls: Vec<String> = raw_urls
        .iter()
        .filter_map(|u| u.as_str())
        .filter_map(|u| crate::turn::normalize_turn_url(u).ok())
        .collect();

    if urls.is_empty() {
        return Err(VkError::Retryable(
            "VK вернул пустой список TURN-серверов".to_string(),
        ));
    }

    log::info!(
        "[VK] получены TURN-креды: user={} urls={}",
        &username,
        urls.len()
    );

    Ok(TurnCredentials {
        username,
        password,
        urls,
    })
}

/// Validates that `hash` looks like a VK join hash before spending a request.
pub fn is_plausible_hash(hash: &str) -> bool {
    let trimmed = hash.trim();
    !trimmed.is_empty()
        && trimmed.len() >= 8
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Extracts the join hash from any of the accepted link shapes.
pub fn hash_from_join_link(link: &str) -> Option<String> {
    crate::config::normalize_vk_hash(link)
}

/// Parses `host:port` TURN URLs from VK into socket addresses.
pub fn parse_turn_urls(urls: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(urls.len());
    for raw in urls {
        let normalized = crate::turn::normalize_turn_url(raw)?;
        // Reject anything that is not host:port.
        let parsed = Url::parse(&format!("turn://{normalized}"))
            .map_err(|e| anyhow!("некорректный TURN URL {raw:?}: {e}"))?;
        if parsed.host_str().is_none() || parsed.port().is_none() {
            bail!("TURN URL без порта: {raw:?}");
        }
        out.push(normalized);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_credentials_are_decoded() {
        // The values shipped in the reference client after de-obfuscation.
        assert_eq!(VK_APP_CREDENTIALS[0].0, "8202606");
        assert_eq!(VK_APP_CREDENTIALS[0].1, "lMRsTiMCyPnp5vfoldmn");
        assert_eq!(VK_APP_CREDENTIALS[1].0, "6287487");
        assert_eq!(VK_APP_CREDENTIALS[1].1, "MuAxFaKDYDOICzGnEOhp");
    }

    #[test]
    fn classifies_call_lifecycle_errors_as_fatal() {
        let dead = serde_json::json!({"error_code": 951, "error_msg": "call is over"});
        assert!(matches!(
            classify_vk_error(&dead),
            Some(VkError::CallUnavailable(_))
        ));
        let gone = serde_json::json!({"error_code": 9005, "error_msg": "gone"});
        assert!(matches!(
            classify_vk_error(&gone),
            Some(VkError::CallUnavailable(_))
        ));
        let rate = serde_json::json!({"error_code": 29, "error_msg": "rate limit"});
        assert!(matches!(
            classify_vk_error(&rate),
            Some(VkError::Retryable(_))
        ));
    }

    #[test]
    fn validates_hashes() {
        assert!(is_plausible_hash(
            "sBvxpZXkz_CAoAstXFslhAZmukJ8rI54l8sJDEbQOO4"
        ));
        assert!(is_plausible_hash("BRtpXEy74qSrZ-6A6QS5THpi9qoQx7"));
        assert!(!is_plausible_hash(""));
        assert!(!is_plausible_hash("short"));
        assert!(!is_plausible_hash("has space"));
        assert!(!is_plausible_hash("bad/char"));
    }

    #[test]
    fn extracts_hash_from_links() {
        assert_eq!(
            hash_from_join_link("https://vk.com/call/join/abc123def").as_deref(),
            Some("abc123def")
        );
        assert_eq!(
            hash_from_join_link("abc123def").as_deref(),
            Some("abc123def")
        );
    }

    #[test]
    fn parses_turn_urls() {
        let urls = vec![
            "turn:82.40.38.237:56005?transport=udp".to_string(),
            "82.40.38.237:56005".to_string(),
        ];
        let parsed = parse_turn_urls(&urls).unwrap();
        assert_eq!(parsed, vec!["82.40.38.237:56005", "82.40.38.237:56005"]);
        assert!(parse_turn_urls(&["turn:host".to_string()]).is_err());
    }

    #[test]
    fn random_names_are_non_empty() {
        for _ in 0..10 {
            let name = random_name();
            assert!(!name.is_empty());
            assert!(name.len() < 32);
        }
    }
}
