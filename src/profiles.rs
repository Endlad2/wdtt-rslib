use anyhow::Result;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::sync::{LazyLock, RwLock};
#[derive(Clone, Debug, Serialize, Deserialize)] pub struct Profile { pub user_agent: String, pub sec_ch_ua: String, pub sec_ch_ua_mobile: String, pub sec_ch_ua_platform: String }
#[derive(Clone, Debug, Serialize, Deserialize)] pub struct SavedProfile { #[serde(flatten)] pub Profile: Profile, pub device_json: String, pub browser_fp: String }
pub const profileFile: &str = "vk_profile.json";
pub fn LoadProfileFromDisk() -> Result<SavedProfile> { Ok(serde_json::from_slice(&std::fs::read(profileFile)?)?) }
fn p(ua:&str, ch:&str, mob:&str, platform:&str)->Profile { Profile{user_agent:ua.into(),sec_ch_ua:ch.into(),sec_ch_ua_mobile:mob.into(),sec_ch_ua_platform:platform.into()} }
pub static profileList: LazyLock<Vec<Profile>> = LazyLock::new(|| vec![p("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36", "\"Chromium\";v=\"146\", \"Not-A.Brand\";v=\"24\", \"Google Chrome\";v=\"146\"", "?0", "\"Windows\""), p("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36", "\"Chromium\";v=\"146\"", "?0", "\"Linux\"")]);
pub static androidProfiles: LazyLock<Vec<Profile>> = LazyLock::new(|| vec![p("Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36", "\"Chromium\";v=\"129\"", "?1", "\"Android\"")]);
pub static iosProfiles: LazyLock<Vec<Profile>> = LazyLock::new(|| vec![p("Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1", "\"Safari\";v=\"17\"", "?1", "\"iOS\"")]);
static activeFingerprint: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new("chrome".into()));
pub fn SetActiveFingerprint(fp: &str) { *activeFingerprint.write().unwrap() = fp.into(); }
pub fn GetActiveFingerprint() -> String { activeFingerprint.read().unwrap().clone() }
pub fn getRandomProfile() -> Profile { let fp=GetActiveFingerprint(); let list=match fp.as_str(){"android"=>&*androidProfiles,"ios"=>&*iosProfiles,_=>&*profileList}; list.choose(&mut rand::thread_rng()).unwrap().clone() }
