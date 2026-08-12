use anyhow::{anyhow, Result};
use serde_json::Value;
use uuid::Uuid;
use std::time::Duration;
use crate::namegen::generateName;
use crate::captcha_v2::{VkCaptchaError, parseVkCaptchaError};

pub const vkConnectClientID: &str = "8093730";
pub const vkCallsAPIHost: &str = "api.vk.me";
pub const vkCallsAnonAPIVersion: &str = "5.276";

#[derive(Debug, Clone)]
pub struct vkCallsFailure {
    pub Step: String,
    pub Kind: String,
    pub Err: String,
}

impl std::fmt::Display for vkCallsFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "step={} kind={}: {}", self.Step, self.Kind, self.Err)
    }
}

impl std::error::Error for vkCallsFailure {}

pub const VK_CALLS_FAILURE_SKIPPED: &str = "skipped";
pub const VK_CALLS_FAILURE_SETUP: &str = "setup";
pub const VK_CALLS_FAILURE_NETWORK: &str = "network";
pub const VK_CALLS_FAILURE_DECODE: &str = "decode";
pub const VK_CALLS_FAILURE_VKAPI: &str = "vk_api";
pub const VK_CALLS_FAILURE_CAPTCHA: &str = "captcha";
pub const VK_CALLS_FAILURE_CALL: &str = "call_unavailable";
pub const VK_CALLS_FAILURE_OKCDN: &str = "okcdn_api";
pub const VK_CALLS_FAILURE_PARSE: &str = "parse";

pub fn newVKCallsFailure(step: &str, kind: &str, err: impl std::fmt::Display) -> anyhow::Error {
    anyhow!(vkCallsFailure {
        Step: step.into(),
        Kind: kind.into(),
        Err: err.to_string()
    })
}

pub fn describeVKCallsFailure(err: &anyhow::Error) -> String {
    err.to_string()
}

pub fn vkCallsAPIErrorKind(err: &anyhow::Error) -> &'static str {
    if let Some(_captcha_err) = err.downcast_ref::<VkCaptchaError>() {
        return VK_CALLS_FAILURE_CAPTCHA;
    }
    if let Some(_call_err) = err.downcast_ref::<CallUnavailableError>() {
        return VK_CALLS_FAILURE_CALL;
    }
    VK_CALLS_FAILURE_VKAPI
}

#[derive(Debug, Clone)]
pub struct vkCallsVKAPIError {
    pub Code: i64,
    pub Message: String,
}

impl std::fmt::Display for vkCallsVKAPIError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error_code={} {}", self.Code, self.Message)
    }
}

impl std::error::Error for vkCallsVKAPIError {}

#[derive(Debug, Clone)]
pub struct vkCallsOKAPIError {
    pub Code: i64,
    pub Message: String,
}

impl std::fmt::Display for vkCallsOKAPIError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error_code={} {}", self.Code, self.Message)
    }
}

impl std::error::Error for vkCallsOKAPIError {}

#[derive(Debug, Clone)]
pub struct CallUnavailableError {
    pub Code: i64,
    pub Message: String,
}

impl std::fmt::Display for CallUnavailableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.Message.is_empty() {
            write!(f, "VK call is unavailable (error_code={})", self.Code)
        } else {
            write!(f, "VK returns error: {} (error_code={})", self.Message, self.Code)
        }
    }
}

impl std::error::Error for CallUnavailableError {}

async fn do_request(
    client: &reqwest::Client,
    step: String,
    url: String,
) -> Result<Value> {
    let response = client
        .post(&url)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")
        .header("Accept", "*/*")
        .header("Accept-Encoding", "gzip, deflate, br, zstd")
        .header("Accept-Language", "en-GB,en;q=0.9")
        .send()
        .await
        .map_err(|e| newVKCallsFailure(&step, VK_CALLS_FAILURE_NETWORK, e))?;

    let body = response
        .text()
        .await
        .map_err(|e| newVKCallsFailure(&step, VK_CALLS_FAILURE_NETWORK, e))?;

    let json: Value = serde_json::from_str(&body)
        .map_err(|e| newVKCallsFailure(&step, VK_CALLS_FAILURE_DECODE, format!("unmarshal JSON: {}, body: {}", e, truncateVKCallsLog(&body, 200))))?;

    Ok(json)
}

pub async fn getVKCredsViaVKCallsPath(link: &str, streamID: i32) -> Result<(String, String, Vec<String>)> {
    if std::env::var("VK_SKIP_VKCALLS").as_deref() == Ok("1") {
        return Err(newVKCallsFailure(
            "preflight",
            VK_CALLS_FAILURE_SKIPPED,
            "disabled by VK_SKIP_VKCALLS=1"
        ));
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;

    let device_id = Uuid::new_v4();
    let name = generateName();
    let link_encoded = url::form_urlencoded::byte_serialize(format!("https://vk.com/call/join/{}", link).as_bytes()).collect::<String>();
    let name_encoded = url::form_urlencoded::byte_serialize(name.as_bytes()).collect::<String>();

    let base = format!("https://{}/method/", vkCallsAPIHost);

    // Step 1: auth.getAnonymToken
    let step1 = "step1 auth.getAnonymToken".to_string();
    let url1 = format!(
        "{}auth.getAnonymToken?v={}&client_id={}&link={}&device_id={}&anonymName={}&lang=en",
        base, vkCallsAnonAPIVersion, vkConnectClientID, link_encoded, device_id, name_encoded
    );
    let resp1 = do_request(&client, step1, url1).await?;
    let anon_token = extractVKCallsStr(&resp1, &["response", "token"])
        .map_err(|e| newVKCallsFailure("step1 auth.getAnonymToken", VK_CALLS_FAILURE_PARSE, format!("parse token: {} (resp: {})", e, truncateVKCallsResp(&resp1))))?;
    let anon_token_encoded = url::form_urlencoded::byte_serialize(anon_token.as_bytes()).collect::<String>();

    // Step 2: messages.getCallPreview
    let step2 = "step2 messages.getCallPreview".to_string();
    let url2 = format!(
        "{}messages.getCallPreview?v={}&anonymous_token={}&device_id={}&extended=1&fields=first_name,last_name,photo_200&lang=en&link={}",
        base, vkCallsAnonAPIVersion, anon_token_encoded, device_id, link_encoded
    );
    let resp2 = do_request(&client, step2, url2).await?;

    if let Some(api_err) = vkCallsAPIError(&resp2) {
        if let Some(_captcha_err) = api_err.downcast_ref::<VkCaptchaError>() {
            eprintln!("[STREAM {}] [VKCalls] step2 captcha gate appeared", streamID);
        } else if let Some(_call_err) = api_err.downcast_ref::<CallUnavailableError>() {
            eprintln!("[STREAM {}] [VKCalls] step2 non-retryable call error", streamID);
        }
        return Err(newVKCallsFailure("step2 messages.getCallPreview", vkCallsAPIErrorKind(&api_err), api_err));
    }

    let user_id = extractVKCallsFloat(&resp2, &["response", "user_id"])
        .map_err(|e| newVKCallsFailure("step2 messages.getCallPreview", VK_CALLS_FAILURE_PARSE, format!("parse user_id: {} (resp: {})", e, truncateVKCallsResp(&resp2))))? as i64;
    let secret = extractVKCallsStr(&resp2, &["response", "secret"])
        .map_err(|e| newVKCallsFailure("step2 messages.getCallPreview", VK_CALLS_FAILURE_PARSE, format!("parse secret: {}", e)))?;

    // Step 3: messages.getAnonymCallToken
    let step3 = "step3 messages.getAnonymCallToken".to_string();
    let url3 = format!(
        "{}messages.getAnonymCallToken?v={}&anonymous_token={}&device_id={}&link={}&name={}&user_id={}&secret={}&lang=en",
        base, vkCallsAnonAPIVersion, anon_token_encoded, device_id, link_encoded,
        name_encoded, user_id, url::form_urlencoded::byte_serialize(secret.as_bytes()).collect::<String>()
    );
    let resp3 = do_request(&client, step3, url3).await?;

    if let Some(api_err) = vkCallsAPIError(&resp3) {
        if let Some(_captcha_err) = api_err.downcast_ref::<VkCaptchaError>() {
            eprintln!("[STREAM {}] [VKCalls] step3 captcha gate appeared", streamID);
        } else if let Some(_call_err) = api_err.downcast_ref::<CallUnavailableError>() {
            eprintln!("[STREAM {}] [VKCalls] step3 non-retryable call error", streamID);
        }
        return Err(newVKCallsFailure("step3 messages.getAnonymCallToken", vkCallsAPIErrorKind(&api_err), api_err));
    }

    let ok_anonym_token = extractVKCallsStr(&resp3, &["response", "token"])
        .map_err(|e| newVKCallsFailure("step3 messages.getAnonymCallToken", VK_CALLS_FAILURE_PARSE, format!("parse token: {} (resp: {})", e, truncateVKCallsResp(&resp3))))?;

    // Step 4: auth.anonymLogin (OK CDN)
    let step4 = "step4 auth.anonymLogin".to_string();
    let ok_device_id = Uuid::new_v4();
    let session_data = format!(
        r#"{{"version":2,"device_id":"{}","client_version":"1.0.1"}}"#,
        ok_device_id
    );
    let url4 = format!(
        "https://calls.okcdn.ru/fb.do?session_data={}&method=auth.anonymLogin&format=JSON&application_key=CGMMEJLGDIHBABABA",
        url::form_urlencoded::byte_serialize(session_data.as_bytes()).collect::<String>()
    );
    let resp4 = do_request(&client, step4, url4).await?;

    let session_key = extractVKCallsStr(&resp4, &["session_key"])
        .map_err(|e| newVKCallsFailure("step4 auth.anonymLogin", VK_CALLS_FAILURE_PARSE, format!("parse session_key: {} (resp: {})", e, truncateVKCallsResp(&resp4))))?;

    // Step 5: vchat.joinConversationByLink (OK CDN)
    let step5 = "step5 vchat.joinConversationByLink".to_string();
    let url5 = format!(
        "https://calls.okcdn.ru/fb.do?joinLink={}&isVideo=false&protocolVersion=5&anonymToken={}&method=vchat.joinConversationByLink&format=JSON&application_key=CGMMEJLGDIHBABABA&session_key={}",
        link, ok_anonym_token, session_key
    );
    let resp5 = do_request(&client, step5, url5).await?;

    if let Some(ok_err) = vkCallsOKError(&resp5) {
        return Err(newVKCallsFailure("step5 vchat.joinConversationByLink", VK_CALLS_FAILURE_OKCDN, ok_err));
    }

    let turn_server = resp5
        .get("turn_server")
        .ok_or_else(|| newVKCallsFailure("step5 vchat.joinConversationByLink", VK_CALLS_FAILURE_PARSE, "missing turn_server"))?;

    let user = turn_server
        .get("username")
        .and_then(Value::as_str)
        .ok_or_else(|| newVKCallsFailure("step5 vchat.joinConversationByLink", VK_CALLS_FAILURE_PARSE, "missing username"))?
        .to_string();

    let pass = turn_server
        .get("credential")
        .and_then(Value::as_str)
        .ok_or_else(|| newVKCallsFailure("step5 vchat.joinConversationByLink", VK_CALLS_FAILURE_PARSE, "missing credential"))?
        .to_string();

    let urls = parseVKCallsTURNAddresses(&resp5);
    if urls.is_empty() {
        return Err(newVKCallsFailure("step5 vchat.joinConversationByLink", VK_CALLS_FAILURE_PARSE, "no TURN addresses"));
    }

    eprintln!("[STREAM {}] [VKCalls] credentials received, TURN urls={}", streamID, urls.len());
    Ok((user, pass, urls))
}

pub fn extractVKCallsStr(v: &Value, keys: &[&str]) -> Result<String> {
    let mut p = v;
    for k in keys {
        p = p.get(k).ok_or_else(|| anyhow!("missing {}", k))?;
    }
    p.as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("not string"))
}

pub fn extractVKCallsFloat(v: &Value, keys: &[&str]) -> Result<f64> {
    let mut p = v;
    for k in keys {
        p = p.get(k).ok_or_else(|| anyhow!("missing {}", k))?;
    }
    p.as_f64()
        .ok_or_else(|| anyhow!("not number"))
}

pub fn parseVKCallsTURNAddresses(v: &Value) -> Vec<String> {
    v.pointer("/turn_server/urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|s| {
            s.split('?')
                .next()
                .unwrap_or(s)
                .trim_start_matches("turn:")
                .trim_start_matches("turns:")
                .to_string()
        })
        .collect()
}

pub fn vkCallsAPIError(v: &Value) -> Option<anyhow::Error> {
    let err_obj = v.get("error")?;
    let obj = err_obj.as_object()?;

    let code = obj
        .get("error_code")
        .and_then(|c| c.as_f64())
        .unwrap_or(0.0) as i64;

    let msg = obj
        .get("error_msg")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();

    if code == 0 && msg.is_empty() {
        return None;
    }

    if let Some(call_err) = fatalCallError(v) {
        return Some(anyhow::Error::new(call_err));
    }

    if code == 14 {
        if let Some(captcha_err) = parseVkCaptchaError(err_obj) {
            return Some(anyhow::Error::new(captcha_err));
        }
    }

    Some(anyhow::Error::new(vkCallsVKAPIError {
        Code: code,
        Message: msg,
    }))
}

pub fn vkCallsOKError(v: &Value) -> Option<anyhow::Error> {
    let code = v
        .get("error_code")
        .and_then(|c| c.as_f64())
        .unwrap_or(0.0) as i64;

    if code == 0 {
        return None;
    }

    let msg = v
        .get("error_msg")
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_string();

    Some(anyhow::Error::new(vkCallsOKAPIError {
        Code: code,
        Message: msg,
    }))
}

pub fn fatalCallError(v: &Value) -> Option<CallUnavailableError> {
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

pub fn truncateVKCallsLog(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect::<String>() + "..."
    }
}

pub fn truncateVKCallsResp(v: &Value) -> String {
    truncateVKCallsLog(&v.to_string(), 200)
}