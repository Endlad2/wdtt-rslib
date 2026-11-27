// SPDX-License-Identifier: LGPL-2.1
//
//! Кросс-платформенный TUN-слой с единым асинхронным API.
//!
//! Модуль нужен, чтобы гонять IPv4-пакеты между WireGuard и системным
//! туннелем: [`TunDevice::read`] отдаёт ровно один IP-пакет за вызов,
//! [`TunDevice::write`] — принимает ровно один.
//!
//! Платформы:
//! - Linux/Android: `/dev/net/tun` + `ioctl(TUNSETIFF)`; асинхронность через
//!   [`tokio::io::unix::AsyncFd`], без блокирующих потоков.
//! - macOS: utun (`PF_SYSTEM`/`SYSPROTO_CONTROL`, `CTLIOCGINFO`). Пакеты в
//!   utun несут 4-байтовый префикс семейства адресов — здесь он
//!   добавляется при записи и срезается при чтении.
//! - Android/iOS: готовый дескриптор от `VpnService`/`NEPacketTunnelProvider`
//!   забирается через [`TunDevice::from_raw_fd`]; сам дескриптор обычно
//!   приходит по unix-сокету — [`receive_fd_from_socket`].
//! - Windows: `wintun.dll` (Wintun), загружается динамически.
//!
//! Настройка адресов и маршрутов — [`TunDevice::configure`] (вызывается
//! после [`TunDevice::create`]).

use std::net::Ipv4Addr;

use anyhow::{bail, Context, Result};

#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(unix)]
use tokio::io::unix::AsyncFd;

/// Минимальный осмысленный MTU: столько обязан принять любой узел IPv4.
pub const MIN_MTU: u16 = 68;
/// Максимальный MTU: IPv4-пакет не бывает длиннее 65 535 байт.
pub const MAX_MTU: u16 = 65535;

/// Сколько ждём дескриптор из unix-сокета (Android/iOS handoff).
#[cfg(unix)]
const FD_HANDOFF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Имя по умолчанию для устройства, полученного через `from_raw_fd`:
/// на utun-платформах дескриптор уже принадлежит utun-интерфейсу.
#[cfg(all(unix, any(target_os = "macos", target_os = "ios")))]
const DEFAULT_TUN_NAME: &str = "utun";
#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
const DEFAULT_TUN_NAME: &str = "tun";

// ---------------------------------------------------------------------------
// Чистая логика (тестируется на любой платформе)
// ---------------------------------------------------------------------------

/// Маска подсети из длины префикса.
///
/// Значения больше 32 обрезаются до 32 — вызывающий код обязан проверить
/// префикс сам (см. `validate_prefix`).
pub fn prefix_to_netmask(prefix: u8) -> [u8; 4] {
    let bits = prefix.min(32) as u32;
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    mask.to_be_bytes()
}

/// Адрес сети для пары `addr`/`prefix`.
pub fn network_of(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = u32::from_be_bytes(prefix_to_netmask(prefix));
    Ipv4Addr::from(u32::from(addr) & mask)
}

/// Проверяет MTU на границы, за которыми TUN работать не будет.
fn validate_mtu(mtu: u16) -> Result<()> {
    if mtu < MIN_MTU {
        bail!("MTU {mtu} слишком мал: минимум {MIN_MTU} байт для IPv4");
    }
    // MAX_MTU is u16::MAX, so an upper-bound check is unreachable by
    // construction; keep the constant for documentation and callers.
    Ok(())
}

/// Проверяет длину префикса IPv4.
fn validate_prefix(prefix: u8) -> Result<()> {
    if prefix > 32 {
        bail!("некорректная длина префикса /{prefix}: допустимо 0..=32");
    }
    Ok(())
}

/// Проверяет имя интерфейса: непустое, без NUL, пробелов и `/`, короче
/// `IFNAMSIZ` (15 символов + завершающий NUL). Шаблон вида `tun%d` допустим.
///
/// Сейчас используется только linux-веткой (`/dev/net/tun`) и тестами.
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
fn validate_interface_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("пустое имя TUN-интерфейса");
    }
    if name.len() >= 16 {
        bail!("имя TUN-интерфейса {name:?} длиннее 15 символов");
    }
    if name.contains('\0') || name.chars().any(|c| c.is_whitespace()) || name.contains('/') {
        bail!("недопустимое имя TUN-интерфейса {name:?}");
    }
    Ok(())
}

/// Разбирает номер utun-интерфейса: `"utun7"` → `Some(7)`.
///
/// `None` означает «номер не задан»: для `"utun"` это запрос свободного
/// unit-а, для любого другого имени — ошибка (проверяется вызывающим кодом).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_utun_unit(name: &str) -> Option<u32> {
    let digits = name.strip_prefix("utun")?;
    if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

// ---------------------------------------------------------------------------
// Общие unix-кирпичи: владение fd, неблокирующий режим, чтение/запись
// ---------------------------------------------------------------------------

/// Владелец сырого дескриптора: закрывает его при уничтожении.
#[cfg(unix)]
struct OwnedTunFd(RawFd);

#[cfg(unix)]
impl AsRawFd for OwnedTunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

#[cfg(unix)]
impl Drop for OwnedTunFd {
    fn drop(&mut self) {
        // Ошибку закрытия обрабатывать нечем: дескриптор всё равно уходит.
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Переводит дескриптор в неблокирующий режим — этого требует `AsyncFd`.
#[cfg(unix)]
fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl(F_GETFL)");
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl(F_SETFL, O_NONBLOCK)");
    }
    Ok(())
}

/// Один `read(2)`; `EINTR` повторяем, остальное — наверх.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
fn read_fd(fd: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

/// Один `write(2)`. Для TUN каждая запись — ровно один пакет, поэтому
/// частичную запись не «доклеиваем», а считаем ошибкой на уровне вызова.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
fn write_fd(fd: RawFd, data: &[u8]) -> std::io::Result<usize> {
    loop {
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

/// Регистрирует дескриптор в tokio.
///
/// `AsyncFd::new` в tokio 1.54 помечен устаревшим: он не описывает владение
/// дескриптором, поэтому используем unsafe-вариант `AsyncFd::register`.
#[cfg(unix)]
fn register_fd(fd: OwnedTunFd) -> Result<AsyncFd<OwnedTunFd>> {
    // Вне рантайма tokio регистрация паникует — отдаём внятную ошибку.
    if tokio::runtime::Handle::try_current().is_err() {
        drop(fd);
        bail!("TunDevice нужно создавать внутри tokio-рантайма: AsyncFd требует реактор");
    }

    // SAFETY: дескриптор принадлежит нам, живёт до Drop AsyncFd и не
    // подменяется — `as_raw_fd` всегда возвращает одно и то же значение.
    match unsafe { AsyncFd::register(fd) } {
        Ok(io) => Ok(io),
        Err(err) => {
            // На ошибке tokio возвращает владение дескриптором: закрываем его.
            let (fd, cause) = err.into_parts();
            drop(fd);
            Err(cause).context("не удалось зарегистрировать TUN-fd в tokio")
        }
    }
}

/// Ждёт готовности дескриптора (`readable`/`writable`) и выполняет операцию.
/// Ложные срабатывания (`EAGAIN`) просто повторяются.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
async fn io_with_ready<F>(
    io: &AsyncFd<OwnedTunFd>,
    readable: bool,
    mut op: F,
) -> std::io::Result<usize>
where
    F: FnMut(RawFd) -> std::io::Result<usize>,
{
    loop {
        let mut guard = if readable {
            io.readable().await?
        } else {
            io.writable().await?
        };
        match guard.try_io(|inner| op(inner.get_ref().as_raw_fd())) {
            Ok(result) => return result,
            // Готовность была ложной — ждём следующую.
            Err(_would_block) => continue,
        }
    }
}

// ---------------------------------------------------------------------------
// Linux / Android: /dev/net/tun
// ---------------------------------------------------------------------------

/// `struct ifreq` из `<net/if.h>`. libc не экспортирует его для linux-gnu,
/// поэтому объявляем сами. 40 байт — размер на 64-битных платформах; ядро
/// копирует `sizeof(struct ifreq)`, поэтому запас не мешает и на 32-битных.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[repr(C)]
struct IfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    /// `ifr_ifru.ifru_flags`: `IFF_TUN | IFF_NO_PI`.
    flags: libc::c_short,
    /// Добиваем структуру до 40 байт, чтобы ядро не читало за нашим буфером.
    _rest: [u8; 22],
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl IfReq {
    fn zeroed() -> Self {
        // Нулевая инициализация — валидное состояние для этой C-структуры.
        unsafe { std::mem::zeroed() }
    }
}

/// Открывает `/dev/net/tun` и создаёт (или подхватывает) интерфейс `name`.
/// Возвращает дескриптор и фактическое имя (ядро могло раскрыть шаблон `%d`).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_linux_tun(name: &str) -> Result<(OwnedTunFd, String)> {
    validate_interface_name(name)?;

    let cname = std::ffi::CString::new(name)
        .with_context(|| format!("имя интерфейса {name:?} содержит NUL"))?;

    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        bail!(
            "не удалось открыть /dev/net/tun: {} (нужны права root и загруженный модуль tun)",
            std::io::Error::last_os_error()
        );
    }
    // Дальше дескриптор нам принадлежит: при ошибке он закроется в Drop.
    let fd = OwnedTunFd(fd);

    let mut req = IfReq::zeroed();
    for (dst, src) in req.name.iter_mut().zip(cname.as_bytes_with_nul()) {
        *dst = *src as libc::c_char;
    }
    req.flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

    let rc = unsafe { libc::ioctl(fd.0, libc::TUNSETIFF, &mut req as *mut IfReq) };
    if rc < 0 {
        bail!(
            "ioctl(TUNSETIFF) для {name:?}: {} (нет прав или имя занято)",
            std::io::Error::last_os_error()
        );
    }

    // Ядро записало фактическое имя обратно в ifr_name.
    let actual = unsafe { std::ffi::CStr::from_ptr(req.name.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let actual = if actual.is_empty() {
        name.to_string()
    } else {
        actual
    };

    Ok((fd, actual))
}

/// Пытается узнать имя TUN-интерфейса по дескриптору (`TUNGETIFF`).
/// Нужно для `from_raw_fd` на Android, где имя задаёт `VpnService`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn tun_name_from_fd(fd: RawFd) -> Option<String> {
    let mut req = IfReq::zeroed();
    let rc = unsafe { libc::ioctl(fd, libc::TUNGETIFF, &mut req as *mut IfReq) };
    if rc < 0 {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(req.name.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Настраивает интерфейс через `ip` из iproute2.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn configure_linux(name: &str, mtu: u16, address: Ipv4Addr, prefix: u8) -> Result<()> {
    let addr_cidr = format!("{address}/{prefix}");
    let mtu = mtu.to_string();

    // Адрес мог остаться с прошлого запуска — «File exists» не ошибка.
    run_command("ip", &["addr", "add", &addr_cidr, "dev", name], true)
        .with_context(|| format!("не удалось назначить {addr_cidr} на {name}"))?;
    run_command("ip", &["link", "set", "mtu", &mtu, "dev", name], false)
        .with_context(|| format!("не удалось выставить MTU {mtu} на {name}"))?;
    run_command("ip", &["link", "set", "dev", name, "up"], false)
        .with_context(|| format!("не удалось поднять {name}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// macOS: utun
// ---------------------------------------------------------------------------

/// Длина префикса семейства адресов в пакете utun.
#[cfg(any(target_os = "macos", target_os = "ios"))]
const UTUN_HEADER_LEN: usize = 4;

#[cfg(target_os = "macos")]
mod utun {
    use super::*;

    /// Имя kernel-контрола utun.
    const UTUN_CONTROL: &std::ffi::CStr = c"com.apple.net.utun_control";
    /// Сколько unit-ов перебираем, если номер не задан явно.
    const MAX_UTUN_UNIT: u32 = 99;

    /// `ioctl(CTLIOCGINFO)`: id контрола по его имени.
    fn control_id() -> Result<u32> {
        let sock =
            unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if sock < 0 {
            bail!(
                "socket(PF_SYSTEM, SYSPROTO_CONTROL): {}",
                std::io::Error::last_os_error()
            );
        }
        let sock = OwnedTunFd(sock);

        let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
        for (dst, src) in info
            .ctl_name
            .iter_mut()
            .zip(UTUN_CONTROL.to_bytes_with_nul())
        {
            *dst = *src as libc::c_char;
        }
        let rc = unsafe {
            libc::ioctl(
                sock.as_raw_fd(),
                libc::CTLIOCGINFO,
                &mut info as *mut libc::ctl_info,
            )
        };
        if rc < 0 {
            bail!(
                "ioctl(CTLIOCGINFO) для {:?}: {}",
                UTUN_CONTROL,
                std::io::Error::last_os_error()
            );
        }
        Ok(info.ctl_id)
    }

    /// Занимает конкретный utun-unit (0-based снаружи, 1-based в ядре).
    /// На каждую попытку — свой сокет: после неудачного `connect` сокет
    /// переиспользовать нельзя.
    fn connect_unit(ctl_id: u32, unit: u32) -> std::io::Result<OwnedTunFd> {
        let sock =
            unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if sock < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let sock = OwnedTunFd(sock);

        let mut addr: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
        addr.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = ctl_id;
        addr.sc_unit = unit + 1;

        let rc = unsafe {
            libc::connect(
                sock.as_raw_fd(),
                &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(sock)
    }

    /// Создаёт utun: либо по явному номеру, либо первый свободный.
    pub(super) fn open(requested: &str) -> Result<(OwnedTunFd, String)> {
        let ctl_id = control_id()?;

        if let Some(unit) = parse_utun_unit(requested) {
            let fd = connect_unit(ctl_id, unit).with_context(|| {
                format!("не удалось подключиться к utun{unit} (занят или нет прав root)")
            })?;
            return Ok((fd, format!("utun{unit}")));
        }

        if !requested.eq_ignore_ascii_case("utun") {
            bail!(
                "некорректное имя TUN для macOS: {requested:?} (ожидается \"utun\" или \"utunN\")"
            );
        }

        for unit in 0..=MAX_UTUN_UNIT {
            match connect_unit(ctl_id, unit) {
                Ok(fd) => {
                    log::debug!("заняли свободный utun{unit}");
                    return Ok((fd, format!("utun{unit}")));
                }
                Err(err) => log::debug!("utun{unit} недоступен: {err}"),
            }
        }
        bail!("не удалось найти свободный utun (перебрали 0..={MAX_UTUN_UNIT})")
    }
}

/// Настраивает utun через `ifconfig` и `route`.
#[cfg(target_os = "macos")]
fn configure_macos(name: &str, mtu: u16, address: Ipv4Addr, prefix: u8) -> Result<()> {
    let addr = address.to_string();
    let mtu = mtu.to_string();

    // Точка-в-точку интерфейс: адрес назначения совпадает с локальным.
    run_command("ifconfig", &[name, &addr, &addr, "mtu", &mtu, "up"], false)
        .with_context(|| format!("не удалось настроить {name}"))?;

    let network = network_of(address, prefix);
    let route = format!("{network}/{prefix}");
    run_command("route", &["add", "-net", &route, "-interface", name], true)
        .with_context(|| format!("не удалось добавить маршрут {route}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Внешние команды (Linux/macOS/Windows)
// ---------------------------------------------------------------------------

/// Запускает внешнюю команду и превращает её stderr в понятную ошибку.
///
/// `ignore_exists` — не считать ошибкой «уже существует» (повторная
/// настройка адреса/маршрута после перезапуска).
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
))]
fn run_command(program: &str, args: &[&str], ignore_exists: bool) -> Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("не удалось запустить {program}"))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    // Разные утилиты говорят по-разному (ip, route, netsh, локали).
    let already_exists = ["File exists", "already exists", "уже существует"]
        .iter()
        .any(|needle| stderr.contains(needle));
    if ignore_exists && already_exists {
        log::debug!("{program} {}: {stderr} (игнорируем)", args.join(" "));
        return Ok(());
    }

    bail!(
        "{program} {} завершилась с {}: {stderr}",
        args.join(" "),
        output.status
    );
}

// ---------------------------------------------------------------------------
// Windows: wintun.dll
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod wintun {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::ptr;

    use anyhow::{bail, Context, Result};

    type Handle = *mut c_void;

    /// Wintun принимает GUID адаптера; `NULL` — «выбери сам».
    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    /// Размер кольцевого буфера сессии (степень двойки, как требует Wintun).
    const SESSION_CAPACITY: u32 = 0x40_0000;
    /// `ERROR_NO_MORE_ITEMS`: пакетов в очереди нет.
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    const WAIT_FAILED: u32 = 0xFFFF_FFFF;
    const WAIT_TIMEOUT: u32 = 258;
    /// Сколько ждём событие чтения за один заход.
    const READ_WAIT_MS: u32 = 1_000;

    // kernel32 есть на любой Windows, поэтому libloading не нужен: грузим DLL
    // через LoadLibraryW/GetProcAddress.
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryW(name: *const u16) -> Handle;
        fn GetProcAddress(module: Handle, name: *const u8) -> *mut c_void;
        fn FreeLibrary(module: Handle) -> i32;
        fn GetLastError() -> u32;
        fn WaitForSingleObject(handle: Handle, millis: u32) -> u32;
    }

    type CreateAdapterFn = unsafe extern "system" fn(*const u16, *const u16, *const Guid) -> Handle;
    type CloseAdapterFn = unsafe extern "system" fn(Handle);
    type StartSessionFn = unsafe extern "system" fn(Handle, u32) -> Handle;
    type EndSessionFn = unsafe extern "system" fn(Handle);
    type GetReadWaitEventFn = unsafe extern "system" fn(Handle) -> Handle;
    type ReceivePacketFn = unsafe extern "system" fn(Handle, *mut u32) -> *mut u8;
    type ReleaseReceivePacketFn = unsafe extern "system" fn(Handle, *const u8);
    type AllocateSendPacketFn = unsafe extern "system" fn(Handle, u32) -> *mut u8;
    type SendPacketFn = unsafe extern "system" fn(Handle, *const u8);

    struct Api {
        create_adapter: CreateAdapterFn,
        close_adapter: CloseAdapterFn,
        start_session: StartSessionFn,
        end_session: EndSessionFn,
        get_read_wait_event: GetReadWaitEventFn,
        receive_packet: ReceivePacketFn,
        release_receive_packet: ReleaseReceivePacketFn,
        allocate_send_packet: AllocateSendPacketFn,
        send_packet: SendPacketFn,
    }

    impl Api {
        fn load(module: Handle) -> Result<Self> {
            Ok(Self {
                create_adapter: symbol(module, c"WintunCreateAdapter")?,
                close_adapter: symbol(module, c"WintunCloseAdapter")?,
                start_session: symbol(module, c"WintunStartSession")?,
                end_session: symbol(module, c"WintunEndSession")?,
                get_read_wait_event: symbol(module, c"WintunGetReadWaitEvent")?,
                receive_packet: symbol(module, c"WintunReceivePacket")?,
                release_receive_packet: symbol(module, c"WintunReleaseReceivePacket")?,
                allocate_send_packet: symbol(module, c"WintunAllocateSendPacket")?,
                send_packet: symbol(module, c"WintunSendPacket")?,
            })
        }
    }

    /// Достаёт символ из DLL и превращает его в указатель на функцию.
    fn symbol<T: Copy>(module: Handle, name: &std::ffi::CStr) -> Result<T> {
        let raw = unsafe { GetProcAddress(module, name.as_ptr().cast()) };
        if raw.is_null() {
            bail!(
                "wintun.dll не экспортирует {}: слишком старая версия (нужна 0.14+)",
                name.to_string_lossy()
            );
        }
        if std::mem::size_of::<T>() != std::mem::size_of::<*mut c_void>() {
            bail!("внутренняя ошибка: размер указателя на функцию не совпадает");
        }
        // Размеры совпадают, указатель получен от самой DLL.
        Ok(unsafe { std::mem::transmute_copy::<*mut c_void, T>(&raw) })
    }

    /// Ищет `wintun.dll`: сначала обычный порядок поиска Windows (рядом с
    /// exe, затем PATH), потом типовые раскладки Wintun.
    fn load_module() -> Result<Handle> {
        let mut candidates: Vec<PathBuf> = vec![PathBuf::from("wintun.dll")];
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                candidates.push(dir.join("wintun.dll"));
                candidates.push(
                    dir.join("wintun")
                        .join("bin")
                        .join("amd64")
                        .join("wintun.dll"),
                );
            }
        }

        for path in &candidates {
            let wide: Vec<u16> = OsStr::new(path.as_os_str())
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let module = unsafe { LoadLibraryW(wide.as_ptr()) };
            if !module.is_null() {
                log::debug!("wintun.dll загружена из {}", path.display());
                return Ok(module);
            }
        }

        bail!(
            "не удалось загрузить wintun.dll (Wintun 0.14+): положите wintun.dll рядом с \
             исполняемым файлом или в <exe>/wintun/bin/amd64/"
        )
    }

    /// Адаптер + сессия Wintun. Создаётся в [`open`], уничтожается в `Drop`.
    pub(super) struct Wintun {
        module: Handle,
        api: Api,
        adapter: Handle,
        session: Handle,
        read_event: Handle,
    }

    // Сессия Wintun потокобезопасна по документации производителя;
    // сырые указатели сами по себе `Send`/`Sync` не являются.
    unsafe impl Send for Wintun {}
    unsafe impl Sync for Wintun {}

    impl Wintun {
        /// Создаёт адаптер с именем `name` и стартует сессию.
        pub(super) fn open(name: &str) -> Result<Self> {
            let module = load_module()?;
            let api = match Api::load(module) {
                Ok(api) => api,
                Err(err) => {
                    unsafe {
                        FreeLibrary(module);
                    }
                    return Err(err);
                }
            };

            let name_w: Vec<u16> = OsStr::new(name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let tunnel_type: Vec<u16> = OsStr::new("WDTToR")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            let adapter =
                unsafe { (api.create_adapter)(name_w.as_ptr(), tunnel_type.as_ptr(), ptr::null()) };
            if adapter.is_null() {
                let err = unsafe { GetLastError() };
                unsafe {
                    FreeLibrary(module);
                }
                bail!("WintunCreateAdapter({name:?}) не удался, код {err} (нужны права администратора)");
            }

            let session = unsafe { (api.start_session)(adapter, SESSION_CAPACITY) };
            if session.is_null() {
                let err = unsafe { GetLastError() };
                unsafe {
                    (api.close_adapter)(adapter);
                    FreeLibrary(module);
                }
                bail!("WintunStartSession({name:?}) не удался, код {err}");
            }

            let read_event = unsafe { (api.get_read_wait_event)(session) };
            if read_event.is_null() {
                let err = unsafe { GetLastError() };
                unsafe {
                    (api.end_session)(session);
                    (api.close_adapter)(adapter);
                    FreeLibrary(module);
                }
                bail!("WintunGetReadWaitEvent({name:?}) не удался, код {err}");
            }

            Ok(Self {
                module,
                api,
                adapter,
                session,
                read_event,
            })
        }

        /// Читает один пакет. Блокирует поток до прихода пакета — вызывать
        /// из отдельной задачи (`spawn_blocking`), а не в общем реакторе.
        pub(super) fn read(&self, buf: &mut [u8]) -> Result<usize> {
            loop {
                let mut size: u32 = 0;
                let ptr = unsafe { (self.api.receive_packet)(self.session, &mut size) };

                if ptr.is_null() {
                    let err = unsafe { GetLastError() };
                    if err == ERROR_NO_MORE_ITEMS {
                        // Пакетов нет — ждём сигнал сессии и пробуем снова.
                        let rc = unsafe { WaitForSingleObject(self.read_event, READ_WAIT_MS) };
                        if rc == WAIT_FAILED {
                            let err = unsafe { GetLastError() };
                            bail!("WaitForSingleObject(сессия Wintun) не удался, код {err}");
                        }
                        if rc == WAIT_TIMEOUT {
                            log::trace!("wintun: пакетов нет за {READ_WAIT_MS} мс");
                        }
                        continue;
                    }
                    bail!("WintunReceivePacket вернул ошибку {err}");
                }

                let size = size as usize;
                if size > buf.len() {
                    unsafe { (self.api.release_receive_packet)(self.session, ptr) };
                    bail!(
                        "пакет из Wintun ({size} байт) больше буфера ({})",
                        buf.len()
                    );
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), size);
                    (self.api.release_receive_packet)(self.session, ptr);
                }
                return Ok(size);
            }
        }

        /// Отправляет один пакет.
        pub(super) fn write(&self, packet: &[u8]) -> Result<usize> {
            let size =
                u32::try_from(packet.len()).context("пакет больше 4 ГиБ — это не IPv4-пакет")?;

            let ptr = unsafe { (self.api.allocate_send_packet)(self.session, size) };
            if ptr.is_null() {
                let err = unsafe { GetLastError() };
                bail!("WintunAllocateSendPacket({size} байт) не удался, код {err}");
            }

            unsafe {
                std::ptr::copy_nonoverlapping(packet.as_ptr(), ptr, packet.len());
                (self.api.send_packet)(self.session, ptr);
            }
            Ok(packet.len())
        }
    }

    impl Drop for Wintun {
        fn drop(&mut self) {
            unsafe {
                (self.api.end_session)(self.session);
                (self.api.close_adapter)(self.adapter);
                FreeLibrary(self.module);
            }
        }
    }
}

/// Настраивает адаптер через `netsh`.
#[cfg(windows)]
fn configure_windows(name: &str, mtu: u16, address: Ipv4Addr, prefix: u8) -> Result<()> {
    let addr = address.to_string();
    let mtu_arg = format!("mtu={mtu}");
    let name_arg = format!("name=\"{name}\"");
    let quoted_name = format!("\"{name}\"");

    run_command(
        "netsh",
        &[
            "interface",
            "ip",
            "set",
            "address",
            &name_arg,
            "static",
            &addr,
            "255.255.255.255",
        ],
        true,
    )
    .with_context(|| format!("не удалось назначить {addr} на {name}"))?;

    run_command(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "subinterface",
            &quoted_name,
            &mtu_arg,
            "store=persistent",
        ],
        false,
    )
    .with_context(|| format!("не удалось выставить MTU {mtu} на {name}"))?;

    // Адрес назначен с маской /32, поэтому маршрут в подсеть туннеля
    // добавляем отдельно.
    let network = network_of(address, prefix);
    let route = format!("{network}/{prefix}");
    run_command(
        "netsh",
        &["interface", "ipv4", "add", "route", &route, &quoted_name],
        true,
    )
    .with_context(|| format!("не удалось добавить маршрут {route}"))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Публичное устройство
// ---------------------------------------------------------------------------

/// Читает/пишет IP-пакеты в системный TUN.
pub struct TunDevice {
    name: String,
    mtu: u16,
    /// На прочих unix (FreeBSD и т.п.) TUN не реализован: дескриптор
    /// принимается и удерживается, но читать/писать через него нечем.
    #[cfg(unix)]
    #[cfg_attr(
        not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios"
        )),
        allow(dead_code)
    )]
    io: AsyncFd<OwnedTunFd>,
    #[cfg(windows)]
    wintun: wintun::Wintun,
}

impl std::fmt::Debug for TunDevice {
    /// Дескрипторы и Wintun-хэндлы в вывод не попадают — только параметры.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunDevice")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .finish()
    }
}

impl TunDevice {
    /// Создаёт TUN с заданным именем и MTU. Только Linux/macOS/Windows.
    ///
    /// На macOS `name` — `"utun"` (первый свободный) или `"utunN"`.
    /// На Android/iOS интерфейс создаёт системный VPN-сервис, поэтому здесь
    /// используется [`TunDevice::from_raw_fd`].
    ///
    /// На Linux/macOS вызывать внутри tokio-рантайма: дескриптор сразу
    /// регистрируется в реакторе (вне рантайма tokio паникует).
    pub fn create(name: &str, mtu: u16) -> Result<Self> {
        validate_mtu(mtu)?;

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let (fd, name) = open_linux_tun(name)?;
            set_nonblocking(fd.as_raw_fd()).context("не удалось включить O_NONBLOCK")?;
            let io = register_fd(fd)?;
            Ok(Self { name, mtu, io })
        }

        #[cfg(target_os = "macos")]
        {
            let (fd, name) = utun::open(name)?;
            set_nonblocking(fd.as_raw_fd()).context("не удалось включить O_NONBLOCK")?;
            let io = register_fd(fd)?;
            Ok(Self { name, mtu, io })
        }

        #[cfg(windows)]
        {
            let wintun = wintun::Wintun::open(name)?;
            Ok(Self {
                name: name.to_string(),
                mtu,
                wintun,
            })
        }

        #[cfg(target_os = "ios")]
        {
            let _ = name;
            bail!(
                "на iOS TUN не создаётся напрямую: получите дескриптор от \
                 NEPacketTunnelProvider и вызовите TunDevice::from_raw_fd"
            )
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            windows
        )))]
        {
            let _ = name;
            bail!("создание TUN не поддерживается на этой платформе")
        }
    }

    /// Забирает уже созданный извне файловый дескриптор (Android/iOS:
    /// `VpnService`/`NEPacketTunnelProvider` отдаёт fd через unix socket).
    ///
    /// # Safety
    ///
    /// `fd` должен быть открытым дескриптором TUN-устройства; владение
    /// переходит к [`TunDevice`] — закрывать его снаружи нельзя.
    pub unsafe fn from_raw_fd(fd: i32, mtu: u16) -> Result<Self> {
        validate_mtu(mtu)?;

        #[cfg(unix)]
        {
            if fd < 0 {
                bail!("некорректный файловый дескриптор: {fd}");
            }
            // Владение сразу переходит к нам: при ошибке дескриптор закроется.
            let owned = OwnedTunFd(fd);
            if let Err(err) = set_nonblocking(fd) {
                drop(owned);
                return Err(err).context("не удалось включить O_NONBLOCK на переданном fd");
            }
            let io = register_fd(owned)?;

            #[cfg(any(target_os = "linux", target_os = "android"))]
            let name = tun_name_from_fd(fd).unwrap_or_else(|| DEFAULT_TUN_NAME.to_string());
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            let name = DEFAULT_TUN_NAME.to_string();

            Ok(Self { name, mtu, io })
        }

        #[cfg(windows)]
        {
            let _ = fd;
            bail!("from_raw_fd не поддерживается на Windows: используйте TunDevice::create")
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = fd;
            bail!("from_raw_fd не поддерживается на этой платформе")
        }
    }

    /// Читает один IP-пакет. Возвращает длину.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < self.mtu as usize {
            bail!(
                "буфер чтения ({} байт) меньше MTU ({}): пакет может не поместиться",
                buf.len(),
                self.mtu
            );
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let n = io_with_ready(&self.io, true, |fd| read_fd(fd, buf))
                .await
                .context("чтение из TUN")?;
            if n == 0 {
                bail!("TUN вернул 0 байт: интерфейс, похоже, закрыт");
            }
            Ok(n)
        }

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            self.read_utun(buf).await
        }

        #[cfg(windows)]
        {
            // Wintun блокирует поток до прихода пакета.
            self.wintun.read(buf)
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            windows
        )))]
        {
            let _ = buf;
            bail!("чтение из TUN не поддерживается на этой платформе")
        }
    }

    /// Пишет один IP-пакет.
    pub async fn write(&self, packet: &[u8]) -> Result<usize> {
        if packet.is_empty() {
            bail!("нельзя отправить пустой пакет в TUN");
        }
        if packet.len() > self.mtu as usize {
            bail!(
                "пакет ({} байт) больше MTU ({}): его нужно фрагментировать выше",
                packet.len(),
                self.mtu
            );
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let n = io_with_ready(&self.io, false, |fd| write_fd(fd, packet))
                .await
                .context("запись в TUN")?;
            if n != packet.len() {
                bail!("в TUN записалось {n} из {} байт", packet.len());
            }
            Ok(n)
        }

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            self.write_utun(packet).await
        }

        #[cfg(windows)]
        {
            self.wintun.write(packet)
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            windows
        )))]
        {
            let _ = packet;
            bail!("запись в TUN не поддерживается на этой платформе")
        }
    }

    /// Настраивает адрес и маршруты. Вызывать после [`TunDevice::create`].
    ///
    /// Linux: `ip addr/link/route`; macOS: `ifconfig` + `route`;
    /// Windows: `netsh`. На Android адреса и маршруты обычно задаёт
    /// `VpnService.Builder`, а на iOS — `NEPacketTunnelProvider`, поэтому
    /// там этот метод ничего не делает.
    pub fn configure(&self, address: Ipv4Addr, prefix: u8) -> Result<()> {
        validate_prefix(prefix)?;
        if address.is_unspecified() {
            bail!("нельзя назначить TUN-интерфейсу адрес 0.0.0.0");
        }
        if address.is_multicast() {
            bail!("нельзя назначить TUN-интерфейсу multicast-адрес {address}");
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            configure_linux(&self.name, self.mtu, address, prefix)
        }

        #[cfg(target_os = "macos")]
        {
            configure_macos(&self.name, self.mtu, address, prefix)
        }

        #[cfg(windows)]
        {
            configure_windows(&self.name, self.mtu, address, prefix)
        }

        #[cfg(target_os = "ios")]
        {
            // Всё уже настроено провайдером туннеля.
            log::debug!("configure на iOS пропущен: адреса задаёт NEPacketTunnelProvider");
            Ok(())
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            windows
        )))]
        {
            bail!("настройка TUN не поддерживается на этой платформе")
        }
    }

    /// Фактическое имя интерфейса (ядро могло раскрыть шаблон `%d`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// MTU, с которым создано устройство.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Чтение utun: срезает 4-байтовый префикс семейства адресов.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    async fn read_utun(&self, buf: &mut [u8]) -> Result<usize> {
        let mut framed = vec![0u8; buf.len() + UTUN_HEADER_LEN];
        let n = io_with_ready(&self.io, true, |fd| read_fd(fd, &mut framed))
            .await
            .context("чтение из utun")?;
        if n == 0 {
            bail!("utun вернул 0 байт: интерфейс, похоже, закрыт");
        }
        if n < UTUN_HEADER_LEN {
            bail!("utun вернул слишком короткий пакет ({n} байт)");
        }

        let family = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]);
        if family != libc::AF_INET as u32 {
            bail!(
                "utun: неожиданное семейство адресов {family}, ожидался AF_INET ({})",
                libc::AF_INET
            );
        }

        let payload_len = n - UTUN_HEADER_LEN;
        buf[..payload_len].copy_from_slice(&framed[UTUN_HEADER_LEN..UTUN_HEADER_LEN + payload_len]);
        Ok(payload_len)
    }

    /// Запись utun: добавляет 4-байтовый префикс `AF_INET` (big-endian).
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    async fn write_utun(&self, packet: &[u8]) -> Result<usize> {
        let mut framed = Vec::with_capacity(packet.len() + UTUN_HEADER_LEN);
        framed.extend_from_slice(&(libc::AF_INET as u32).to_be_bytes());
        framed.extend_from_slice(packet);

        let n = io_with_ready(&self.io, false, |fd| write_fd(fd, &framed))
            .await
            .context("запись в utun")?;
        if n != framed.len() {
            bail!("в utun записалось {n} из {} байт", framed.len());
        }
        Ok(packet.len())
    }
}

// ---------------------------------------------------------------------------
// Приём дескриптора по unix-сокету (Android/iOS handoff)
// ---------------------------------------------------------------------------

/// Удаляет файл сокета при выходе из [`receive_fd_from_socket`].
#[cfg(unix)]
struct SocketPathGuard(std::path::PathBuf);

#[cfg(unix)]
impl Drop for SocketPathGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Выравнивание управляющих сообщений (`CMSG_ALIGN` из `<sys/socket.h>`):
/// на Linux — `sizeof(size_t)`, на Darwin — 4 байта, на прочих unix —
/// размер указателя.
#[cfg(unix)]
fn cmsg_align(len: usize) -> usize {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const ALIGN: usize = std::mem::size_of::<libc::size_t>();
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const ALIGN: usize = 4;
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    const ALIGN: usize = std::mem::size_of::<usize>();

    (len + ALIGN - 1) & !(ALIGN - 1)
}

/// `CMSG_LEN(0)`: заголовок cmsg с учётом выравнивания.
#[cfg(unix)]
fn cmsg_header_len() -> usize {
    cmsg_align(std::mem::size_of::<libc::cmsghdr>())
}

/// `CMSG_SPACE(data_len)`: сколько занимает cmsg с данными `data_len`.
#[cfg(unix)]
fn cmsg_space(data_len: usize) -> usize {
    cmsg_header_len() + cmsg_align(data_len)
}

/// Получает fd из unix SOCK_DGRAM socketpair (Android/iOS handoff).
///
/// Слушает unix datagram socket по пути `socket_path`, принимает один
/// SCM_RIGHTS-дескриптор и возвращает его. Ждёт не дольше 30 секунд.
/// Владение полученным дескриптором переходит к вызывающему.
#[cfg(unix)]
pub fn receive_fd_from_socket(socket_path: &str) -> Result<i32> {
    use std::os::unix::net::UnixDatagram;

    let path = std::path::Path::new(socket_path);
    // bind не перезаписывает существующий файл: убираем хвост прошлого запуска.
    match std::fs::remove_file(path) {
        Ok(()) => log::debug!("удалён устаревший сокет {socket_path}"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err)
                .with_context(|| format!("не удалось удалить старый сокет {socket_path}"))
        }
    }

    let sock = UnixDatagram::bind(path)
        .with_context(|| format!("не удалось забиндить unix-сокет {socket_path}"))?;
    let _cleanup = SocketPathGuard(path.to_path_buf());

    // std выставляет SO_RCVTIMEO, а его уважает и сырой recvmsg.
    sock.set_read_timeout(Some(FD_HANDOFF_TIMEOUT))
        .with_context(|| format!("не удалось выставить таймаут на {socket_path}"))?;

    recv_single_fd(sock.as_raw_fd(), socket_path)
}

/// `recvmsg` + разбор SCM_RIGHTS: ровно один дескриптор.
#[cfg(unix)]
fn recv_single_fd(fd: RawFd, socket_path: &str) -> Result<i32> {
    let mut payload = [0u8; 64];
    // u64-массив гарантирует выравнивание под cmsghdr.
    let mut cmsg_space_buf = [0u64; 8];

    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr().cast(),
        iov_len: payload.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_space_buf.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&cmsg_space_buf) as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        let err = std::io::Error::last_os_error();
        if matches!(
            err.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ) {
            bail!(
                "таймаут {} с: дескриптор из {socket_path} не пришёл",
                FD_HANDOFF_TIMEOUT.as_secs()
            );
        }
        return Err(err).with_context(|| format!("recvmsg из {socket_path}"));
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        bail!("управляющие данные из {socket_path} не поместились (MSG_CTRUNC)");
    }

    let ctrl_len = msg.msg_controllen as usize;
    let base = msg.msg_control as *const u8;
    let header_len = cmsg_header_len();
    let mut fds: Vec<i32> = Vec::new();
    let mut offset = 0usize;

    while offset + header_len <= ctrl_len {
        // Буфер контролируем сами: смещения кратны выравниванию cmsg.
        let cmsg = unsafe { base.add(offset) } as *const libc::cmsghdr;
        let cmsg_len = unsafe { (*cmsg).cmsg_len } as usize;
        if cmsg_len < header_len || offset + cmsg_len > ctrl_len {
            bail!("некорректный cmsg_len={cmsg_len} из {socket_path} (буфер {ctrl_len})");
        }
        let data_len = cmsg_len - header_len;

        let level = unsafe { (*cmsg).cmsg_level };
        let kind = unsafe { (*cmsg).cmsg_type };
        if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
            let count = data_len / std::mem::size_of::<libc::c_int>();
            let data = unsafe { base.add(offset + header_len) } as *const libc::c_int;
            for i in 0..count {
                fds.push(unsafe { *data.add(i) });
            }
        }

        offset += cmsg_space(data_len);
    }

    match fds.len() {
        1 => Ok(fds[0]),
        0 => bail!("в сообщении из {socket_path} не было SCM_RIGHTS-дескриптора"),
        n => {
            // Чужие дескрипторы не должны утечь.
            for fd in &fds {
                unsafe {
                    libc::close(*fd);
                }
            }
            bail!("из {socket_path} пришло {n} дескрипторов, ожидался ровно один")
        }
    }
}

// ---------------------------------------------------------------------------
// Тесты
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_from_prefix() {
        assert_eq!(prefix_to_netmask(0), [0, 0, 0, 0]);
        assert_eq!(prefix_to_netmask(8), [255, 0, 0, 0]);
        assert_eq!(prefix_to_netmask(16), [255, 255, 0, 0]);
        assert_eq!(prefix_to_netmask(20), [255, 255, 240, 0]);
        assert_eq!(prefix_to_netmask(24), [255, 255, 255, 0]);
        assert_eq!(prefix_to_netmask(30), [255, 255, 255, 252]);
        assert_eq!(prefix_to_netmask(32), [255, 255, 255, 255]);
        // Больше 32 — обрезаем, а не паникуем.
        assert_eq!(prefix_to_netmask(33), [255, 255, 255, 255]);
        assert_eq!(prefix_to_netmask(255), [255, 255, 255, 255]);
    }

    #[test]
    fn network_from_address_and_prefix() {
        let addr = Ipv4Addr::new(192, 168, 1, 77);
        assert_eq!(network_of(addr, 24), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(network_of(addr, 32), addr);
        assert_eq!(network_of(addr, 0), Ipv4Addr::UNSPECIFIED);

        let addr = Ipv4Addr::new(10, 1, 2, 3);
        assert_eq!(network_of(addr, 8), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(network_of(addr, 16), Ipv4Addr::new(10, 1, 0, 0));

        let addr = Ipv4Addr::new(172, 16, 5, 4);
        assert_eq!(network_of(addr, 12), Ipv4Addr::new(172, 16, 0, 0));
        assert_eq!(network_of(addr, 30), Ipv4Addr::new(172, 16, 5, 4));

        // 192.168.1.0/31 — сеть без «нулевого» адреса.
        let addr = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(network_of(addr, 31), Ipv4Addr::new(192, 168, 1, 0));
    }

    #[test]
    fn utun_name_parsing() {
        assert_eq!(parse_utun_unit("utun0"), Some(0));
        assert_eq!(parse_utun_unit("utun7"), Some(7));
        assert_eq!(parse_utun_unit("utun42"), Some(42));
        assert_eq!(parse_utun_unit("utun99"), Some(99));

        // «utun» без номера — запрос свободного unit-а, не ошибка разбора.
        assert_eq!(parse_utun_unit("utun"), None);
        // Не-utun имена и мусор.
        assert_eq!(parse_utun_unit("tun0"), None);
        assert_eq!(parse_utun_unit(""), None);
        assert_eq!(parse_utun_unit("utunx"), None);
        assert_eq!(parse_utun_unit("utun1a"), None);
        assert_eq!(parse_utun_unit("utun 5"), None);
        assert_eq!(parse_utun_unit("utun-1"), None);
        assert_eq!(parse_utun_unit("utun1234"), None);
        assert_eq!(parse_utun_unit("utun_1"), None);
    }

    #[test]
    fn mtu_bounds() {
        assert!(validate_mtu(MIN_MTU).is_ok());
        assert!(validate_mtu(1420).is_ok());
        assert!(validate_mtu(1500).is_ok());
        assert!(validate_mtu(MAX_MTU).is_ok());

        assert!(validate_mtu(0).is_err());
        assert!(validate_mtu(MIN_MTU - 1).is_err());
        assert!(validate_mtu(67).is_err());
    }

    #[test]
    fn prefix_bounds() {
        for prefix in 0..=32u8 {
            assert!(
                validate_prefix(prefix).is_ok(),
                "префикс /{prefix} должен быть валиден"
            );
        }
        assert!(validate_prefix(33).is_err());
        assert!(validate_prefix(255).is_err());
    }

    #[test]
    fn interface_name_validation() {
        assert!(validate_interface_name("tun0").is_ok());
        assert!(validate_interface_name("utun7").is_ok());
        assert!(validate_interface_name("tun%d").is_ok());
        assert!(validate_interface_name("wdtt-tun").is_ok());
        assert!(validate_interface_name(&"a".repeat(15)).is_ok());

        assert!(validate_interface_name("").is_err());
        assert!(validate_interface_name(&"a".repeat(16)).is_err());
        assert!(validate_interface_name("tun 0").is_err());
        assert!(validate_interface_name("tun/0").is_err());
        assert!(validate_interface_name("tun\0").is_err());
    }

    /// Сверяем собственные CMSG-хелперы с макросами libc (Linux/Android).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn cmsg_helpers_match_libc() {
        for data_len in [0u32, 4, 8, 12, 16, 20] {
            assert_eq!(
                cmsg_header_len(),
                unsafe { libc::CMSG_LEN(0) } as usize,
                "CMSG_LEN(0) для data_len={data_len}"
            );
            assert_eq!(
                cmsg_space(data_len as usize),
                unsafe { libc::CMSG_SPACE(data_len) } as usize,
                "CMSG_SPACE({data_len})"
            );
        }
        assert_eq!(cmsg_align(0), 0);
        assert!(cmsg_align(1).is_power_of_two());
        assert_eq!(cmsg_space(1), cmsg_header_len() + cmsg_align(1));
    }
}
