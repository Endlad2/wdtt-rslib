use anyhow::Result;
use std::fs;

pub const VK_EXCLUDED_IPS: &str = r#"AllowedIPs = 0.0.0.0/6, 4.0.0.0/8, 5.0.0.0/11, 5.32.0.0/12, 5.48.0.0/13, 5.56.0.0/14, 5.60.0.0/16, 5.61.0.0/20, 5.61.24.0/21, 5.61.32.0/19, 5.61.64.0/18, 5.61.128.0/18, 5.61.192.0/19, 5.61.224.0/21, 5.61.240.0/20, 5.62.0.0/15, 5.64.0.0/11, 5.96.0.0/14, 5.100.0.0/16, 5.101.0.0/19, 5.101.32.0/21, 5.101.44.0/22, 5.101.48.0/20, 5.101.64.0/18, 5.101.128.0/17, 5.102.0.0/15, 5.104.0.0/13, 5.112.0.0/12, 5.128.0.0/11, 5.160.0.0/12, 5.176.0.0/14, 5.180.0.0/16, 5.181.0.0/19, 5.181.32.0/20, 5.181.48.0/21, 5.181.56.0/22, 5.181.64.0/18, 5.181.128.0/17, 5.182.0.0/15, 5.184.0.0/14, 5.188.0.0/17, 5.188.128.0/21, 5.188.136.0/22, 5.188.144.0/20, 5.188.160.0/19, 5.188.192.0/18, 5.189.0.0/16, 5.190.0.0/15, 5.192.0.0/10"#;

pub fn process_wireguard_config(raw_config: &str) -> Result<String> {
    let mut result = String::new();
    let lines: Vec<&str> = raw_config.lines().collect();
    
    let mut in_interface = false;
    let mut in_peer = false;
    let mut has_interface_mtu = false;
    let mut has_peer_allowed_ips = false;
    
    for line in &lines {
        let trimmed = line.trim();
        
        if trimmed == "[Interface]" {
            in_interface = true;
            in_peer = false;
            result.push_str(line);
            result.push('\n');
            continue;
        }
        
        if trimmed == "[Peer]" {
            in_interface = false;
            in_peer = true;
            result.push_str(line);
            result.push('\n');
            continue;
        }
        
        if in_interface && trimmed.starts_with("MTU =") {
            has_interface_mtu = true;
            result.push_str("MTU = 1280\n");
            continue;
        }
        
        if in_peer && trimmed.starts_with("AllowedIPs =") {
            has_peer_allowed_ips = true;
            result.push_str(VK_EXCLUDED_IPS);
            result.push('\n');
            continue;
        }
        
        if in_peer && trimmed.starts_with("Endpoint =") {
            continue; // Пропускаем оригинальный Endpoint
        }
        
        // Добавляем остальные строки
        result.push_str(line);
        result.push('\n');
    }
    
    // Добавляем MTU если не было
    if !has_interface_mtu {
        // Найти [Interface] и вставить после него
        let mut new_result = String::new();
        for line in result.lines() {
            new_result.push_str(line);
            new_result.push('\n');
            if line.trim() == "[Interface]" {
                new_result.push_str("MTU = 1280\n");
            }
        }
        result = new_result;
    }
    
    // Добавляем AllowedIPs если не было
    if !has_peer_allowed_ips {
        let mut new_result = String::new();
        for line in result.lines() {
            new_result.push_str(line);
            new_result.push('\n');
            if line.trim() == "[Peer]" {
                new_result.push_str(VK_EXCLUDED_IPS);
                new_result.push('\n');
            }
        }
        result = new_result;
    }
    
    // Добавляем Endpoint = 127.0.0.1:9000 если его нет
    if !result.contains("Endpoint = 127.0.0.1:9000") {
        let mut new_result = String::new();
        for line in result.lines() {
            new_result.push_str(line);
            new_result.push('\n');
            if line.trim() == "[Peer]" && !result.contains("Endpoint = 127.0.0.1:9000") {
                new_result.push_str("Endpoint = 127.0.0.1:9000\n");
            }
        }
        result = new_result;
    }
    
    Ok(result)
}

pub fn save_config(config: &str) -> Result<()> {
    let processed = process_wireguard_config(config)?;
    fs::write("config.toml", processed)?;
    eprintln!("[КОНФИГ] Сохранён в config.toml (MTU=1280, Endpoint=127.0.0.1:9000, VK IP excluded)");
    Ok(())
}