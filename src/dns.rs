pub const yandexDNSServers: [&str;2] = ["77.88.8.8:53","77.88.8.1:53"];
pub fn setupGlobalResolver() { /* Tokio resolver is configured by the embedding application. */ }
pub fn isYandexDNSAddress(address:&str)->bool { let h=address.trim().trim_start_matches('[').split([':',']']).next().unwrap_or(""); h=="77.88.8.8"||h=="77.88.8.1" }
