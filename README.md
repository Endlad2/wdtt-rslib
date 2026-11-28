# WDTToR — Rust-клиент WDTT

Обратно совместимый с сервером WDTT клиент: **WireGuard поверх TURN/DTLS**
с RTP-обфускацией. Написан на Rust ради кроссплатформенности — один и тот же
код работает на Linux, Windows, macOS, Android и в OpenWrt.

Протокол повторяет оригинал ([proxy-turn-vk-android](https://github.com/amurcanov/proxy-turn-vk-android))
байт в байт, поэтому подходит к любому серверу WDTT без изменений на сервере.

## Что внутри

```
TUN  ──►  boringtun (WireGuard)  ──►  UDP 127.0.0.1:<local>
                                          │
                                          ▼
                                     диспетчер (round-robin по 12 пакетов)
                                          │
                          ┌───────────────┼───────────────┐
                          ▼               ▼               ▼
                      сессия #1       сессия #2  ...  сессия #N
                          │               │               │
                   TURN allocate → relay → DTLS (AES-128-GCM)
                          │               │               │
                          └───────────────┼───────────────┘
                                          ▼
                              RTP + ChaCha20-Poly1305 (WRAP)
                                          ▼
                                   сервер WDTT
```

* **TUN** — через [`boringtun`](https://github.com/cloudflare/boringtun), как и
  в оригинале, где стоит WireGuard.
* **Транспорт** — TURN-аллокация на серверах VK, поверх неё DTLS.
* **Обфускация** — каждый пакет выглядит как RTP-пакет медиапотока:
  PT 111 (audio) или 96 (video), случайный SSRC, «правильные» seq/timestamp,
  случайный padding. Полезная нагрузка зашифрована ChaCha20-Poly1305, ключ
  выводится из пароля подключения через HKDF-SHA256 (`WDTT-WRAP-v1`).
* **Креды TURN** получаются у VK двумя путями: `vkcalls` (по умолчанию,
  обычно без капчи) и `legacy`.

## Совместимость с сервером

| Что | Значение |
| --- | --- |
| WRAP KDF | HKDF-SHA256, salt `WDTT-WRAP-v1`, info `rtp-obfs/chacha20poly1305` |
| AEAD nonce | `SSRC(4) ‖ seq(2) ‖ 0x0000 ‖ timestamp(4)`, AAD = 12-байтовый RTP-заголовок |
| Payload types | 111 (audio, padding ≤ 24), 96 (video, padding ≤ 60) |
| DTLS | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, extended master secret **required** |
| Управляющий протокол | `GETCONF:<port>|<device>|<password>` → конфиг WG / `NOCONF` / `DENIED:<reason>` |
| Готовность | `READY` → `READY_OK`, затем сырые WireGuard-датаграммы |
| Keepalive | 1 байт `0xFF` каждые 15 с |

Совместимость проверена на живом сервере: клиент получает TURN-креды у VK,
поднимает DTLS, забирает конфиг WireGuard и **проходит ICMP-пинг через
туннель** (`--self-test`).

## Сборка

```bash
cargo build --release
```

Готовые бинарники для всех платформ собирает GitHub Actions
(`.github/workflows/build.yml`):

| Платформа | Артефакт |
| --- | --- |
| Linux x86_64 (glibc) | `wdtt-core-linux-x86_64` |
| Linux musl (x86_64, aarch64, armv7) | `wdtt-openwrt-*` |
| Windows x86_64 | `wdtt-core-windows-x86_64.exe` |
| macOS (universal) | `wdtt-core-macos-universal` |
| Android (arm64-v8a, armeabi-v7a, x86_64) | `wdtt-android-multiabi.zip` (`jniLibs/*/libwdtt.so`) |

## Запуск

Самый простой способ — ссылка `wdtt://`:

```bash
wdtt-rslib --link 'wdtt://82.40.38.237:56005:56006:9000:ПАРОЛЬ:ХЕШ1,ХЕШ2,ХЕШ3'
```

Формат ссылки: `wdtt://<ip>:<порт DTLS>:<порт WG>:<локальный порт>:<пароль>:<хеши>`.

Альтернатива — отдельные флаги:

```bash
wdtt-rslib \
  --peer 82.40.38.237:56005 \
  --password 'ПАРОЛЬ' \
  --vk 'ХЕШ1,ХЕШ2' \
  --listen 127.0.0.1:9000 \
  --workers 9
```

### Проверка туннеля

```bash
wdtt-rslib --link 'wdtt://…' --self-test
```

Клиент поднимает туннель без TUN и пингует сервер ICMP-эхом через него.
Успех выглядит так:

```
[SELFTEST] ✓✓ ТУННЕЛЬ РАБОТАЕТ: 30 из 30 ICMP-ответов через WDTT
SELFTEST_OK: 30/30 ICMP replies received
```

### Флаги

| Флаг | По умолчанию | Назначение |
| --- | --- | --- |
| `--link` | — | ссылка `wdtt://` |
| `--peer`, `--password`, `--vk` | — | то же по частям |
| `-n, --workers` | `9` | число сессий (кратно 9, максимум 108) |
| `--listen` | `127.0.0.1:9000` | локальный WireGuard-эндпоинт |
| `--obfs` | `audio` | `audio` или `video` |
| `--vk-auth-mode` | `vkcalls` | `vkcalls` или `legacy` |
| `--device-id` | `wdtt-rs` | ID устройства (привязка пароля на сервере) |
| `--tun-name` | `wdtt0` | имя TUN-интерфейса |
| `--mtu` | из конфига | MTU TUN |
| `--no-tun` | выкл. | только локальный эндпоинт, без TUN |
| `--packet-port` | — | отдавать сырые IP-пакеты по UDP (Android VpnService) |
| `--tun-fd-socket` | — | взять fd TUN из unix-сокета (Android/iOS) |
| `--turn`, `--port` | — | переопределить TURN-сервер (отладка) |
| `--self-test` | выкл. | пинг через туннель без TUN |
| `--events` | выкл. | машинные события `__WDTT_EVENT__\|…` |
| `--log-level` | `info` | `error`, `warn`, `info`, `debug`, `trace` |

### Режим без root (Android)

На Android нельзя открыть `/dev/net/tun`, поэтому интерфейс создаёт
`VpnService`, а ядро отдаёт сырые IP-пакеты по UDP:

```bash
wdtt-rslib --link 'wdtt://…' --packet-port 127.0.0.1:52230 --listen 127.0.0.1:9100
```

Хост-приложение присылает на `52230` IP-пакеты из своего интерфейса и получает
ответы обратно с того же адреса; WireGuard ядро делает само. Проверено на живом
сервере: 15 из 15 ICMP-ответов.

### События для host-приложения

При `--events` (или `WDTT_EVENTS=1`) в stdout печатаются строки, совместимые с
оригинальным клиентом:

```
__WDTT_EVENT__|STARTED|{"version":"0.2.0","workers":9,...}
__WDTT_EVENT__|READY|
__WDTT_EVENT__|CONFIG|{"config":"[Interface]\n..."}
__WDTT_EVENT__|STATS|{"active":9,"bytes_up":123,"bytes_down":456}
__WDTT_EVENT__|ERROR|{"code":"FATAL","message":"...","fatal":true}
__WDTT_EVENT__|STOPPED|
```

## Как это работает по шагам

1. **Креды.** Для хеша VK-звонка клиент получает у VK логин/пароль TURN:
   `vkcalls` — цепочка `auth.getAnonymToken` → `messages.getCallPreview` →
   `messages.getAnonymCallToken` → `auth.anonymLogin` →
   `vchat.joinConversationByLink`; при неудаче — `legacy` через `calls.*`.
2. **TURN.** На каждый воркер — своя аллокация на одном из TURN-серверов VK,
   с периодическим STUN binding refresh.
3. **DTLS.** Поверх relay поднимается DTLS-сессия с self-signed сертификатом.
4. **Обфускация.** Все пакеты оборачиваются в RTP+AEAD; ключ — из пароля.
5. **Конфиг.** Первая сессия шлёт `GETCONF`, получает WireGuard-конфиг с ключами
   и адресом (`10.x.x.N/32`), отдаёт его host-приложению событием `CONFIG`.
6. **WireGuard.** boringtun инкапсулирует пакеты из TUN в WireGuard-датаграммы,
   которые уходят на локальный эндпоинт и дальше в сессии.
7. **Диспетчер.** Раскидывает датаграммы по сессиям блоками по 12 штук, чтобы
   не ломать порядок внутри DTLS-записи и использовать все воркеры.

## Тесты

```bash
cargo test
```

74 теста: разбор ссылок и конфигов, WRAP/обфускация (включая известный ответ
HKDF), RTP-заголовки, диспетчер на реальных UDP-сокетах, WireGuard-хендшейк
между двумя peers на boringtun, ICMP-пакеты, а также сквозные тесты, где
реализована серверная сторона протокола (TURN-релей, DTLS, `GETCONF`).

## Сигналы для host-приложения

Помимо структурированных событий ядро печатает строки, которые разбирают
готовые host-приложения (LaLune на Android/Desktop):

```
TUNCONF:10.9.0.52:1.1.1.1                              # адрес и DNS для интерфейса
[СТАТИСТИКА] Активных: 9 | Трафик: 1.25 МБ             # как в оригинале
[READY] туннель готов                                  # WireGuard-хендшейк прошёл
```

## Ограничения

* Сервер WDTT должен быть поднят и пароль — действующим.
* VK может потребовать капчу: тогда креды не выдаются (это ограничение самого
  VK, а не клиента; в оригинале для этого есть встроенный WebView).
* На Linux для собственного TUN нужны права root и загруженный модуль `tun`;
  на Android/iOS интерфейс создаёт host-приложение и передаёт fd.
* На Windows рядом с `wdtt-rslib.exe` нужен `wintun.dll` (как и для любого
  WireGuard-клиента).
* Android собирается под **API 24+**: `getifaddrs`/`freeifaddrs` появились
  только в API 24, на API 21 линковка падает.
* mips/mipsel не собираются: для них нет готового `rust-std` (tier-3),
  нужна сборка std из исходников. На таких роутерах WDTToR пока недоступен.

## Лицензия

LGPL-2.1 (совместимо с оригиналом).
