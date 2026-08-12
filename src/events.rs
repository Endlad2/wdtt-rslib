use serde_json::{json, Value}; use std::sync::LazyLock;
pub type eventType = &'static str; pub const eventStarted:eventType="STARTED"; pub const eventStopped:eventType="STOPPED"; pub const eventReady:eventType="READY"; pub const eventConfig:eventType="CONFIG"; pub const eventStats:eventType="STATS"; pub const eventError:eventType="ERROR"; pub const eventCaptchaRequest:eventType="CAPTCHA_REQUEST"; pub const eventCaptchaDone:eventType="CAPTCHA_DONE";
static EVENT_OUTPUT_ENABLED: LazyLock<bool> = LazyLock::new(|| std::env::var("WDTT_EVENTS").as_deref()==Ok("1"));
pub fn emitEvent(t:eventType,payload:Value){if *EVENT_OUTPUT_ENABLED { println!("__WDTT_EVENT__|{t}|{payload}"); }}
pub fn emitError(code:&str,message:&str,fatal:bool){emitEvent(eventError,json!({"code":code,"message":message,"fatal":fatal}));}
pub fn emitStats(s:&crate::stats::Stats){use std::sync::atomic::Ordering;emitEvent(eventStats,json!({"active":s.ActiveConnections.load(Ordering::Relaxed),"bytes_up":s.TotalBytesUp.load(Ordering::Relaxed),"bytes_down":s.TotalBytesDown.load(Ordering::Relaxed)}));}
pub fn emitReady(){emitEvent(eventReady,Value::Null)} pub fn emitConfig(config:&str){emitEvent(eventConfig,json!({"config":config}));}
pub fn emitCaptchaRequest(mode:&str,redirectURI:&str,sessionToken:&str){emitEvent(eventCaptchaRequest,json!({"mode":mode,"redirect_uri":redirectURI,"session_token":sessionToken}));} pub fn emitCaptchaDone(success:bool,err:&str){emitEvent(eventCaptchaDone,json!({"success":success,"error":err}));}
