use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::Rng;
use regex::Regex;
use reqwest::Client;
use serde_json::Value;
use sha2::{Sha256, Digest};
use std::sync::LazyLock;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct VkCaptchaError {
    pub captcha_sid: String,
    pub redirect_uri: String,
    pub session_token: String,
    pub captcha_ts: String,
    pub captcha_attempt: String,
}

impl std::fmt::Display for VkCaptchaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VK captcha sid={}", self.captcha_sid)
    }
}

impl std::error::Error for VkCaptchaError {}

pub const CAPTCHA_V2_API_VERSION: &str = "5.131";
pub const CAPTCHA_V2_SCRIPT_VERSION: &str = "1.1.1370";
pub const CAPTCHA_V2_DEVICE_INFO: &str = r#"{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1040,"innerWidth":1920,"innerHeight":970,"devicePixelRatio":1,"language":"ru-RU","languages":["ru-RU","ru","en-US","en"],"webdriver":false,"hardwareConcurrency":8,"notificationsPermission":"default"}"#;

pub const CAPTCHA_V2_MAX_ATTEMPTS: usize = 10;

pub static RE_CAPTCHA_V2_POW_INPUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"const\s+powInput\s*=\s*"([^"]+)""#).unwrap());
pub static RE_CAPTCHA_V2_DIFFICULTY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"const\s+difficulty\s*=\s*(\d+)"#).unwrap());
pub static RE_CAPTCHA_V2_WINDOW_INIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?s)window\.init\s*=\s*(\{.*?})\s*;"#).unwrap());
pub static RE_CAPTCHA_V2_SCRIPT_SRC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"src="(https://[^"]+not_robot_captcha[^"]+)""#).unwrap());
pub static RE_CAPTCHA_V2_DEBUG_INFO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"debug_info:(?:[^"]*\|\|)?"([a-fA-F0-9]{64})""#).unwrap());
pub static RE_CAPTCHA_V2_VERSION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"vkid/([0-9.]*)/not_robot_captcha\.js"#).unwrap());

pub const CAPTCHA_V2_HEADER_ORDER: [&str; 15] = [
    "host",
    "content-length",
    "sec-ch-ua-platform",
    "accept-language",
    "sec-ch-ua",
    "content-type",
    "sec-ch-ua-mobile",
    "user-agent",
    "accept",
    "origin",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    "referer",
    "accept-encoding",
];

pub const CAPTCHA_V2_PHEADER_ORDER: [&str; 4] = [":method", ":path", ":authority", ":scheme"];

#[derive(Debug, Clone)]
pub struct captchaV2Init {
    pub data: captchaV2InitData,
}

#[derive(Debug, Clone)]
pub struct captchaV2InitData {
    pub show_captcha_type: String,
    pub captcha_settings: Vec<captchaV2InitSetting>,
}

#[derive(Debug, Clone)]
pub struct captchaV2InitSetting {
    pub r#type: String,
    pub settings: String,
}

#[derive(Debug, Clone)]
pub struct captchaV2Page {
    pub pow_input: String,
    pub pow_difficulty: i32,
    pub script_url: String,
    pub init: Option<captchaV2Init>,
}

#[derive(Debug, Clone)]
pub struct captchaV2Check {
    pub status: String,
    pub success_token: String,
    pub show_type: String,
}

#[derive(Debug)]
pub struct captchaV2ShowTypeError {
    pub show_type: String,
}

impl std::fmt::Display for captchaV2ShowTypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "captcha show type mismatch: {}", self.show_type)
    }
}

impl std::error::Error for captchaV2ShowTypeError {}

static DEBUG_CACHE: std::sync::OnceLock<std::collections::HashMap<String, String>> =
    std::sync::OnceLock::new();

fn get_debug_cache() -> &'static std::collections::HashMap<String, String> {
    DEBUG_CACHE.get_or_init(std::collections::HashMap::new)
}

pub fn captchaV2BaseValues(session_token: &str) -> Vec<(&str, String)> {
    vec![
        ("session_token", session_token.to_string()),
        ("domain", "vk.com".to_string()),
        ("adFp", "".to_string()),
        ("access_token", "".to_string()),
    ]
}

pub fn captchaV2BrowserFP() -> Result<String> {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill(&mut bytes);
    Ok(hex::encode(bytes))
}

pub fn captchaV2EncodeForm(values: &[(&str, String)]) -> String {
    let mut parts = Vec::new();
    for (k, v) in values {
        parts.push(format!("{}={}", 
            url::form_urlencoded::byte_serialize(k.as_bytes()).collect::<String>(),
            url::form_urlencoded::byte_serialize(v.as_bytes()).collect::<String>()
        ));
    }
    parts.join("&")
}

pub fn captchaV2QueryEscape(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

pub fn captchaV2StringifyAny(value: &Value) -> String {
    match value {
        Value::Null => "".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(|v| captchaV2StringifyAny(v)).collect();
            format!("[{}]", items.join(","))
        }
        Value::Object(obj) => {
            let items: Vec<String> = obj
                .iter()
                .map(|(k, v)| format!("{}:{}", k, captchaV2StringifyAny(v)))
                .collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

pub fn parseVkCaptchaError(err_data: &Value) -> Option<VkCaptchaError> {
    let obj = err_data.as_object()?;
    let code = obj.get("error_code").and_then(|v| v.as_f64()).unwrap_or(0.0) as i32;
    if code != 14 {
        return None;
    }

    let redirect_uri = obj
        .get("redirect_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let captcha_sid = obj
        .get("captcha_sid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| obj.get("captcha_sid").and_then(|v| v.as_f64()).map(|n| n.to_string()))
        .unwrap_or_default();

    let session_token = if !redirect_uri.is_empty() {
        url::Url::parse(&redirect_uri)
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find(|(k, _)| k == "session_token")
                    .map(|(_, v)| v.to_string())
            })
            .unwrap_or_default()
    } else {
        String::new()
    };

    let captcha_ts = obj
        .get("captcha_ts")
        .and_then(|v| v.as_f64())
        .map(|n| n.to_string())
        .or_else(|| obj.get("captcha_ts").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .unwrap_or_default();

    let captcha_attempt = obj
        .get("captcha_attempt")
        .and_then(|v| v.as_f64())
        .map(|n| n.to_string())
        .or_else(|| obj.get("captcha_attempt").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .unwrap_or_default();

    Some(VkCaptchaError {
        captcha_sid,
        redirect_uri,
        session_token,
        captcha_ts,
        captcha_attempt,
    })
}

pub fn parseCaptchaV2Page(html: &str) -> Result<captchaV2Page> {
    let init_json = RE_CAPTCHA_V2_WINDOW_INIT
        .captures(html)
        .and_then(|cap| cap.get(1))
        .ok_or_else(|| anyhow!("captcha init json not found"))?
        .as_str();

    let init_data: Value = serde_json::from_str(init_json)?;

    let mut init = captchaV2Init {
        data: captchaV2InitData {
            show_captcha_type: String::new(),
            captcha_settings: Vec::new(),
        },
    };

    if let Some(data) = init_data.get("data") {
        if let Some(show_type) = data.get("show_captcha_type").and_then(|v| v.as_str()) {
            init.data.show_captcha_type = show_type.to_string();
        }
        if let Some(settings) = data.get("captcha_settings").and_then(|v| v.as_array()) {
            for item in settings {
                if let (Some(t), Some(s)) = (item.get("type").and_then(|v| v.as_str()), item.get("settings").and_then(|v| v.as_str())) {
                    init.data.captcha_settings.push(captchaV2InitSetting {
                        r#type: t.to_string(),
                        settings: s.to_string(),
                    });
                }
            }
        }
    }

    let script_url = RE_CAPTCHA_V2_SCRIPT_SRC
        .captures(html)
        .and_then(|cap| cap.get(1))
        .ok_or_else(|| anyhow!("captcha script url not found"))?
        .as_str()
        .to_string();

    let pow_input = RE_CAPTCHA_V2_POW_INPUT
        .captures(html)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    let pow_difficulty = if let Some(cap) = RE_CAPTCHA_V2_DIFFICULTY.captures(html) {
        if let Some(m) = cap.get(1) {
            m.as_str().parse::<i32>().unwrap_or(0)
        } else {
            0
        }
    } else {
        0
    };

    Ok(captchaV2Page {
        pow_input,
        pow_difficulty,
        script_url,
        init: Some(init),
    })
}

pub fn parseCaptchaV2Check(raw: &Value) -> Result<captchaV2Check> {
    let resp = raw
        .get("response")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow!("invalid captcha check response: {:?}", raw))?;

    let status = resp
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if status.is_empty() {
        return Err(anyhow!("captcha check status missing: {:?}", raw));
    }

    Ok(captchaV2Check {
        success_token: resp
            .get("success_token")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        show_type: resp
            .get("show_captcha_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        status,
    })
}

pub fn solveCaptchaPoWV2(input: &str, difficulty: i32) -> String {
    if input.is_empty() || difficulty <= 0 {
        return String::new();
    }

    let target = "0".repeat(difficulty as usize);
    let mut rng = rand::thread_rng();

    let delay_ms = 200 + rng.gen_range(0..300);
    std::thread::sleep(Duration::from_millis(delay_ms));

    for nonce in 1..=10_000_000 {
        if nonce % 4096 == 0 {
            // Проверка на отмену (в реальном коде нужно передавать ctx)
        }
        let hash_input = format!("{}{}", input, nonce);
        let hash = Sha256::digest(hash_input.as_bytes());
        let hash_hex = hex::encode(hash);
        if hash_hex.starts_with(&target) {
            return hash_hex;
        }
    }
    String::new()
}

pub async fn captchaRequest(client: &Client, method: &str, form: &[(&str, String)]) -> Result<Value> {
    let url = format!("https://api.vk.ru/method/{}?v={}", method, CAPTCHA_V2_API_VERSION);
    
    let body = captchaV2EncodeForm(form);
    
    let response = client
        .post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Origin", "https://id.vk.com")
        .header("Referer", "https://id.vk.com/")
        .body(body)
        .send()
        .await?;
    
    let text = response.text().await?;
    let json: Value = serde_json::from_str(&text)?;
    
    Ok(json)
}

pub async fn performCaptchaCheck(
    client: &Client,
    session_token: &str,
    browser_fp: &str,
    hash: &str,
    answer_json: &str,
    cursor: &str,
    debug_info: &str,
) -> Result<captchaV2Check> {
    let values = vec![
        ("session_token", session_token.to_string()),
        ("domain", "vk.com".to_string()),
        ("adFp", "".to_string()),
        ("accelerometer", "[]".to_string()),
        ("gyroscope", "[]".to_string()),
        ("motion", "[]".to_string()),
        ("cursor", cursor.to_string()),
        ("taps", "[]".to_string()),
        ("connectionRtt", "[]".to_string()),
        ("connectionDownlink", "[]".to_string()),
        ("browser_fp", browser_fp.to_string()),
        ("hash", hash.to_string()),
        ("answer", STANDARD.encode(answer_json.as_bytes())),
        ("debug_info", debug_info.to_string()),
        ("access_token", "".to_string()),
    ];
    
    let values_ref: Vec<(&str, String)> = values.iter()
        .map(|(k, v)| (*k, v.clone()))
        .collect();
    
    let resp = captchaRequest(client, "captchaNotRobot.check", &values_ref).await?;
    parseCaptchaV2Check(&resp)
}

pub async fn fetchCaptchaHTML(client: &Client, redirect_uri: &str) -> Result<String> {
    let response = client
        .get(redirect_uri)
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header("Sec-Fetch-Dest", "document")
        .header("Sec-Fetch-Mode", "navigate")
        .header("Sec-Fetch-Site", "cross-site")
        .send()
        .await?;
    
    let text = response.text().await?;
    Ok(text)
}

pub async fn fetchDebugInfo(client: &Client, script_url: &str) -> Result<String> {
    // Проверяем кэш
    if let Some(cached) = get_debug_cache().get(script_url) {
        return Ok(cached.clone());
    }
    
    let response = client
        .get(script_url)
        .header("Accept", "text/javascript,*/*")
        .header("Referer", "https://id.vk.com/")
        .send()
        .await?;
    
    let text = response.text().await?;
    
    let debug_info = RE_CAPTCHA_V2_DEBUG_INFO
        .captures(&text)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| anyhow!("debug_info match not found"))?;
    
    // TODO: Сохранять в кэш с RwLock
    
    Ok(debug_info)
}

pub async fn solveCheckboxCaptcha(
    client: &Client,
    session_token: &str,
    browser_fp: &str,
    hash: &str,
    debug_info: &str,
) -> Result<String> {
    let device_json = CAPTCHA_V2_DEVICE_INFO;
    
    let _ = captchaRequest(client, "captchaNotRobot.componentDone", &[
        ("session_token", session_token.to_string()),
        ("domain", "vk.com".to_string()),
        ("adFp", "".to_string()),
        ("browser_fp", browser_fp.to_string()),
        ("device", device_json.to_string()),
        ("access_token", "".to_string()),
    ]).await?;
    
    let mut rng = rand::thread_rng();
    let delay_ms = 400 + rng.gen_range(0..250);
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    
    let check = performCaptchaCheck(
        client,
        session_token,
        browser_fp,
        hash,
        "{}",
        "[]",
        debug_info,
    ).await?;
    
    if !check.show_type.is_empty() && !check.show_type.eq_ignore_ascii_case("checkbox") {
        return Err(anyhow!("{}", captchaV2ShowTypeError { show_type: check.show_type }));
    }
    
    if check.status.eq_ignore_ascii_case("error_limit") {
        return Err(anyhow!("captcha session rate limit reached"));
    }
    
    if check.status.eq_ignore_ascii_case("bot") {
        return Err(anyhow!("checkbox captcha rejected: status={}", check.status));
    }
    
    if !check.status.eq_ignore_ascii_case("ok") {
        return Err(anyhow!("checkbox captcha rejected: status={}", check.status));
    }
    
    if check.success_token.is_empty() {
        return Err(anyhow!("captcha success token not found"));
    }
    
    Ok(check.success_token)
}

pub async fn solveSliderCaptcha(
    client: &Client,
    session_token: &str,
    browser_fp: &str,
    hash: &str,
    _settings: &str,
    debug_info: &str,
) -> Result<String> {
    let values = captchaV2BaseValues(session_token);
    let resp = captchaRequest(client, "captchaNotRobot.getContent", &values).await?;
    
    let puzzle = crate::captcha_v2_slider::parseSliderPuzzleV2(&resp)?;
    
    let guesses = crate::captcha_v2_slider::rankSliderGuessesV2(
        &puzzle.image,
        puzzle.size,
        &puzzle.swaps,
    )?;
    
    let limit = puzzle.attempts.min(guesses.len());
    if limit == 0 {
        return Err(anyhow!("slider has no attempts available"));
    }
    
    let device_json = CAPTCHA_V2_DEVICE_INFO;
    let _ = captchaRequest(client, "captchaNotRobot.componentDone", &[
        ("session_token", session_token.to_string()),
        ("domain", "vk.com".to_string()),
        ("adFp", "".to_string()),
        ("access_token", "".to_string()),
        ("browser_fp", browser_fp.to_string()),
        ("device", device_json.to_string()),
    ]).await?;
    
    for (_i, guess) in guesses.iter().take(limit).enumerate() {
        let answer = serde_json::json!({"value": guess.swaps});
        let answer_json = serde_json::to_string(&answer)?;
        let cursor = crate::captcha_v2_slider::buildSliderCursorV2(guess.index, guesses.len());
        
        let check = performCaptchaCheck(
            client,
            session_token,
            browser_fp,
            hash,
            &answer_json,
            &cursor,
            debug_info,
        ).await?;
        
        if check.status.eq_ignore_ascii_case("ok") {
            if check.success_token.is_empty() {
                return Err(anyhow!("captcha success token not found"));
            }
            return Ok(check.success_token);
        }
        
        if check.status.eq_ignore_ascii_case("error_limit") {
            return Err(anyhow!("captcha session rate limit reached"));
        }
    }
    
    Err(anyhow!("slider guesses exhausted"))
}

pub async fn solveVkCaptchaV2(
    captcha_err: &VkCaptchaError,
    client: &Client,
    _profile: &crate::profiles::Profile,
    saved_profile: Option<&crate::profiles::SavedProfile>,
) -> Result<String> {
    solveVkCaptchaV2Attempts(captcha_err, client, saved_profile, CAPTCHA_V2_MAX_ATTEMPTS).await
}

pub async fn solveVkCaptchaV2Attempts(
    captcha_err: &VkCaptchaError,
    client: &Client,
    saved_profile: Option<&crate::profiles::SavedProfile>,
    max_attempts: usize,
) -> Result<String> {
    if captcha_err.session_token.is_empty() {
        return Err(anyhow!("no session_token in redirect_uri"));
    }

    let max_attempts = max_attempts.max(1);
    let mut last_error: Option<anyhow::Error> = None;
    
    for attempt in 1..=max_attempts {
        match solve_vk_captcha_once(captcha_err, client, saved_profile).await {
            Ok(token) => return Ok(token),
            Err(e) => {
                last_error = Some(e);
                let backoff = (attempt * 500).min(5000);
                tokio::time::sleep(Duration::from_millis(backoff as u64)).await;
            }
        }
    }
    
    Err(last_error.unwrap_or_else(|| anyhow!("captcha attempts exhausted")))
}

async fn solve_vk_captcha_once(
    captcha_err: &VkCaptchaError,
    client: &Client,
    saved_profile: Option<&crate::profiles::SavedProfile>,
) -> Result<String> {
    let html = fetchCaptchaHTML(client, &captcha_err.redirect_uri).await?;
    let page = parseCaptchaV2Page(&html)?;
    
    if page.pow_input.is_empty() {
        return Err(anyhow!("failed to find PoW settings"));
    }
    
    let slider_settings = page.init.as_ref().and_then(|init| {
        init.data.captcha_settings.iter()
            .find(|s| s.r#type == "slider")
            .map(|s| s.settings.clone())
    }).unwrap_or_default();
    
    let hash = solveCaptchaPoWV2(&page.pow_input, page.pow_difficulty);
    if hash.is_empty() {
        return Err(anyhow!("captcha pow failed"));
    }
    
    let values = captchaV2BaseValues(&captcha_err.session_token);
    let _ = captchaRequest(client, "captchaNotRobot.settings", &values).await?;
    
    let browser_fp = if let Some(sp) = saved_profile {
        if !sp.browser_fp.is_empty() {
            sp.browser_fp.clone()
        } else {
            captchaV2BrowserFP()?
        }
    } else {
        captchaV2BrowserFP()?
    };
    
    let debug_info = fetchDebugInfo(client, &page.script_url).await?;
    
    let mut show_type = page.init.as_ref()
        .map(|init| init.data.show_captcha_type.clone())
        .unwrap_or_default();
    
    loop {
        let result = match show_type.as_str() {
            "slider" => {
                solveSliderCaptcha(
                    client,
                    &captcha_err.session_token,
                    &browser_fp,
                    &hash,
                    &slider_settings,
                    &debug_info,
                ).await
            }
            "checkbox" | "" => {
                solveCheckboxCaptcha(
                    client,
                    &captcha_err.session_token,
                    &browser_fp,
                    &hash,
                    &debug_info,
                ).await
            }
            _ => {
                return Err(anyhow!("unsupported captcha type: {}", show_type));
            }
        };
        
        match result {
            Ok(token) => {
                let _ = captchaRequest(client, "captchaNotRobot.endSession", &values).await;
                return Ok(token);
            }
            Err(e) => {
                if e.to_string().contains("bot") && show_type != "slider" && !slider_settings.is_empty() {
                    show_type = "slider".to_string();
                    continue;
                }
                return Err(e);
            }
        }
    }
}