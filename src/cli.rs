use std::env;
use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const STATE: &str = "/run/passkey";
const KEYS: &str = "/etc/passkey/u2f_keys";
const NAMES: &str = "/etc/passkey/names";
const DROPIN: &str = "/etc/systemd/system/passkeyd.service.d/user.conf";
const MARK: &str = "# passkey: fingerprint from your Android device (undo with: passkey uninstall)";
const PARALLEL: &[&str] = &["sudo", "sudo-i", "su", "login", "polkit-1"];
const ON_EMPTY: &[&str] = &["kde", "plasmalogin", "sddm", "gdm-password", "lightdm"];

pub fn run(command: &str, args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        "add" => add(args.first().map(String::as_str)),
        "list" => {
            print_devices(&current_user()?)?;
            Ok(())
        }
        "remove" => remove(
            args.first()
                .ok_or("usage: passkey remove <number or name>")?,
        ),
        "status" => status(),
        "uninstall" => privileged(&["root-uninstall"], None),
        "root-configure" => {
            require_root()?;
            configure(args.first().ok_or("missing user")?)
        }
        "root-use" => {
            require_root()?;
            root_use(
                args.first().map(String::as_str),
                args.get(1).map(String::as_str),
            )
        }
        "root-store" => {
            require_root()?;
            root_store(args.first().ok_or("missing user")?)
        }
        "root-remove" => {
            require_root()?;
            root_remove(
                args.first().ok_or("missing user")?,
                args.get(1).ok_or("missing credential")?,
            )
        }
        "root-uninstall" => {
            require_root()?;
            uninstall()
        }
        "help" | "--help" | "-h" => {
            println!(
                "Usage: passkey <command>\n\nCommands:\n  add [name]\n  list\n  remove <number or name>\n  status\n  uninstall"
            );
            Ok(())
        }
        _ => Err(format!("unknown command {command:?}; run `passkey help`").into()),
    }
}

fn add(given_name: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let user = current_user()?;
    check_environment()?;
    privileged(&["root-configure", &user], None)?;
    println!("Open the Passkey app on your Android device (USB cable or Bluetooth)...");
    let deadline = Instant::now() + Duration::from_secs(90);
    while virtual_device().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_secs(2));
    }
    if virtual_device().is_none() {
        return Err("no device appeared".into());
    }

    let connections = connected_devices()?;
    let selected = select_connection(&connections)?;
    if let Some((id, _)) = &selected {
        let pid = std::process::id().to_string();
        privileged(&["root-use", id, &pid], None)?;
    }
    struct ClearUse(bool);
    impl Drop for ClearUse {
        fn drop(&mut self) {
            if self.0 {
                let _ = privileged(&["root-use"], None);
            }
        }
    }
    let _clear = ClearUse(selected.is_some());

    let existing = names_for(&user)?;
    let base = selected
        .as_ref()
        .map(|(_, label)| label.trim())
        .filter(|label| !label.is_empty())
        .unwrap_or("Android device");
    let mut default = base.to_string();
    let mut suffix = 2;
    while existing.iter().any(|name| name == &default) {
        default = format!("{base} {suffix}");
        suffix += 1;
    }
    let mut name = given_name.unwrap_or_default().trim().to_string();
    if name.is_empty() && io::stdin().is_terminal() {
        print!("Name for this device [{default}]: ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut name)?;
        name = name.trim().to_string();
    }
    if name.is_empty() {
        name = default;
    }
    name = name.replace(['\t', '\n', '\r'], " ");
    if existing.iter().any(|old| old == &name) {
        return Err(format!("device name {name:?} is already used").into());
    }

    println!("Confirm with your fingerprint on the device...");
    let origin = format!("pam://{}", hostname()?);
    let output = Command::new("pamu2fcfg")
        .args(["-u", &user, "-o", &origin, "-i", &origin, "-V", "-n"])
        .output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_string()
            .into());
    }
    let credential = String::from_utf8(output.stdout)?.trim().to_string();
    if !credential.starts_with(':') || !credential.contains(',') {
        return Err("pamu2fcfg returned an invalid credential".into());
    }
    privileged(
        &["root-store", &user],
        Some(format!("{credential}\n{name}\n").as_bytes()),
    )?;
    println!("Done: {name:?} is registered.");
    Ok(())
}

fn remove(which: &str) -> Result<(), Box<dyn std::error::Error>> {
    let user = current_user()?;
    let handles = handles_for(&user)?;
    let names = names_for(&user)?;
    let index = names
        .iter()
        .enumerate()
        .find(|(index, name)| which == (index + 1).to_string() || which == name.as_str())
        .map(|(index, _)| index)
        .ok_or_else(|| format!("no registered device {which:?}"))?;
    privileged(&["root-remove", &user, &handles[index]], None)?;
    println!("Removed {:?}.", names[index]);
    Ok(())
}

fn status() -> Result<(), Box<dyn std::error::Error>> {
    let running = Command::new("systemctl")
        .args(["is-active", "--quiet", "passkeyd.service"])
        .status()
        .is_ok_and(|status| status.success());
    println!(
        "service: {}",
        if running { "running" } else { "not running" }
    );
    println!(
        "device: {}",
        virtual_device().unwrap_or_else(|| "not connected".into())
    );
    for service in PARALLEL.iter().chain(ON_EMPTY) {
        if fs::read_to_string(format!("/etc/pam.d/{service}"))
            .is_ok_and(|text| text.lines().any(is_ours))
        {
            println!("PAM: {service}");
        }
    }
    if let Err(error) = check_environment() {
        eprintln!("{error}");
    }
    println!("registered:");
    print_devices(&current_user()?)?;
    Ok(())
}

fn print_devices(user: &str) -> Result<(), Box<dyn std::error::Error>> {
    let names = names_for(user)?;
    if names.is_empty() {
        println!("  No devices registered.");
    } else {
        for (index, name) in names.iter().enumerate() {
            println!("  {}  {name}", index + 1);
        }
    }
    Ok(())
}

fn configure(user: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new("/etc/pam.d").is_dir() {
        return Err("this system does not use Linux-PAM".into());
    }
    if !Path::new("/dev/uhid").exists() {
        let _ = Command::new("modprobe").arg("uhid").status();
    }
    if !Path::new("/dev/uhid").exists() {
        return Err("/dev/uhid is unavailable; the kernel needs CONFIG_UHID".into());
    }

    if has_systemd() {
        write_file(
            Path::new(DROPIN),
            format!("[Service]\nEnvironment=PASSKEY_ADB_USER={user}\n").as_bytes(),
            0o644,
        )?;
        Command::new("systemctl").arg("daemon-reload").status()?;
        let enabled = Command::new("systemctl")
            .args(["enable", "--now", "passkeyd.service"])
            .status()?;
        if !enabled.success() {
            return Err("could not enable passkeyd.service".into());
        }
    }
    for service in PARALLEL.iter().chain(ON_EMPTY) {
        pam_add(service)?;
    }
    Ok(())
}

fn uninstall() -> Result<(), Box<dyn std::error::Error>> {
    for service in PARALLEL.iter().chain(ON_EMPTY) {
        pam_remove(service)?;
    }
    if has_systemd() {
        let _ = Command::new("systemctl")
            .args(["disable", "--now", "passkeyd.service"])
            .status();
    }
    let _ = fs::remove_dir_all("/etc/systemd/system/passkeyd.service.d");
    let _ = fs::remove_dir_all("/etc/passkey");
    if has_systemd() {
        let _ = Command::new("systemctl").arg("daemon-reload").status();
    }
    println!("Configuration and registrations removed.");
    Ok(())
}

fn pam_line(service: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mode = if ON_EMPTY.contains(&service) {
        "on-empty"
    } else {
        "parallel"
    };
    let origin = format!("pam://{}", hostname()?);
    let u2f = format!("authfile={KEYS} origin={origin} appid={origin} userverification=1 nouserok");
    // pam_passkey hands a typed password to the next module; a stack whose
    // pam_unix does not take it (try_first_pass / use_first_pass, missing in
    // Debian's common-auth) would ask for it twice, so there plain pam_u2f
    // asks the device first.
    if pam_module_dir().is_some_and(|dir| dir.join("pam_passkey.so").is_file())
        && unix_takes_password()
    {
        Ok(format!(
            "-auth      sufficient   pam_passkey.so mode={mode} {u2f}"
        ))
    } else {
        Ok(format!(
            "-auth      sufficient   pam_u2f.so {u2f} cue [cue_prompt=Confirm with your fingerprint on your device, or reject there to type your password]"
        ))
    }
}

fn pam_add(service: &str) -> Result<(), Box<dyn std::error::Error>> {
    let etc = PathBuf::from(format!("/etc/pam.d/{service}"));
    let vendor = PathBuf::from(format!("/usr/lib/pam.d/{service}"));
    let (source, copied) = if etc.exists() {
        (etc.clone(), false)
    } else if vendor.exists() {
        (vendor, true)
    } else {
        return Ok(());
    };
    let input = fs::read_to_string(&source)?;
    let wanted = pam_line(service)?;
    if input.lines().any(|line| line == wanted) {
        return Ok(());
    }
    let mut output = Vec::new();
    let mut inserted = false;
    for line in input.lines() {
        if line == MARK {
            output.push(line);
            continue;
        }
        if is_ours(line) {
            if !inserted {
                output.push(wanted.as_str());
                inserted = true;
            }
            continue;
        }
        if !inserted && is_auth(line) && !is_guard(line) {
            // A mark with no line of ours after it (an older install) is kept once.
            if output.last() == Some(&MARK) {
                output.pop();
            }
            output.push(MARK);
            output.push(wanted.as_str());
            inserted = true;
        }
        output.push(line);
    }
    if !inserted {
        return Ok(());
    }
    let text = format!("{}\n", output.join("\n"));
    let destination = if copied {
        etc.clone()
    } else {
        fs::canonicalize(&etc)?
    };
    write_file(&destination, text.as_bytes(), 0o644)?;
    if copied {
        write_file(
            Path::new(&format!("/etc/passkey/copied/{service}")),
            b"",
            0o644,
        )?;
    }
    Ok(())
}

fn pam_remove(service: &str) -> Result<(), Box<dyn std::error::Error>> {
    let etc = PathBuf::from(format!("/etc/pam.d/{service}"));
    if !etc.exists() {
        return Ok(());
    }
    let input = fs::read_to_string(&etc)?;
    if !input.lines().any(is_ours) {
        return Ok(());
    }
    let restored = format!(
        "{}\n",
        input
            .lines()
            .filter(|line| !is_ours(line))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let marker = PathBuf::from(format!("/etc/passkey/copied/{service}"));
    let vendor = PathBuf::from(format!("/usr/lib/pam.d/{service}"));
    if marker.exists() && vendor.exists() && fs::read_to_string(&vendor)? == restored {
        fs::remove_file(&etc)?;
    } else {
        write_file(&fs::canonicalize(&etc)?, restored.as_bytes(), 0o644)?;
    }
    let _ = fs::remove_file(marker);
    Ok(())
}

fn is_auth(line: &str) -> bool {
    let line = line
        .trim_start()
        .strip_prefix('-')
        .unwrap_or(line.trim_start());
    line == "auth" || line.starts_with("auth ") || line.starts_with("auth\t")
}

fn is_guard(line: &str) -> bool {
    [
        "pam_nologin.so",
        "pam_securetty.so",
        "pam_shells.so",
        "pam_rootok.so",
    ]
    .iter()
    .any(|name| line.contains(name))
        || line.contains("pam_faillock.so") && line.contains("preauth")
}

fn is_ours(line: &str) -> bool {
    line == MARK
        || ((line.contains("pam_passkey.so") || line.contains("pam_u2f.so"))
            && line.contains(&format!("authfile={KEYS}")))
}

fn root_use(device: Option<&str>, pid: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(STATE).join("use");
    if let Some(device) = device {
        write_file(
            &path,
            format!("{device} {}\n", pid.ok_or("missing owner pid")?).as_bytes(),
            0o644,
        )?;
        Ok(())
    } else {
        let _ = fs::remove_file(path);
        Ok(())
    }
}

fn root_store(user: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let mut lines = input.lines();
    let credential = lines.next().ok_or("missing credential")?;
    let name = lines.next().ok_or("missing name")?;
    if !credential.starts_with(':') || name.contains(['\t', '\n', '\r']) {
        return Err("invalid registration data".into());
    }
    let handle = credential
        .trim_start_matches(':')
        .split(',')
        .next()
        .ok_or("invalid credential")?;
    let mut key_lines = read_optional(KEYS)?
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if let Some(line) = key_lines
        .iter_mut()
        .find(|line| line.starts_with(&format!("{user}:")))
    {
        line.push_str(credential);
    } else {
        key_lines.push(format!("{user}{credential}"));
    }
    let mut names = lines_file(&read_optional(NAMES)?.lines().collect::<Vec<_>>());
    names.push_str(&format!("{user}\t{handle}\t{name}\n"));
    write_file(Path::new(KEYS), lines_file(&key_lines).as_bytes(), 0o644)?;
    write_file(Path::new(NAMES), names.as_bytes(), 0o644)?;
    Ok(())
}

fn root_remove(user: &str, handle: &str) -> Result<(), Box<dyn std::error::Error>> {
    let keys = fs::read_to_string(KEYS)?;
    let names = read_optional(NAMES)?;
    let mut out = Vec::new();
    for line in keys.lines() {
        if !line.starts_with(&format!("{user}:")) {
            out.push(line.to_string());
            continue;
        }
        let mut fields = line.split(':');
        let owner = fields.next().unwrap_or_default();
        let credentials = fields
            .filter(|credential| credential.split(',').next() != Some(handle))
            .collect::<Vec<_>>();
        if !credentials.is_empty() {
            out.push(format!("{owner}:{}", credentials.join(":")));
        }
    }
    write_file(Path::new(KEYS), lines_file(&out).as_bytes(), 0o644)?;
    let names = names
        .lines()
        .filter(|line| {
            let mut fields = line.split('\t');
            fields.next() != Some(user) || fields.next() != Some(handle)
        })
        .collect::<Vec<_>>();
    write_file(Path::new(NAMES), lines_file(&names).as_bytes(), 0o644)?;
    Ok(())
}

fn handles_for(user: &str) -> io::Result<Vec<String>> {
    let keys = read_optional(KEYS)?;
    Ok(keys
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{user}:")))
        .unwrap_or_default()
        .split(':')
        .filter_map(|credential| credential.split(',').next())
        .filter(|handle| !handle.is_empty())
        .map(str::to_owned)
        .collect())
}

fn names_for(user: &str) -> io::Result<Vec<String>> {
    let handles = handles_for(user)?;
    let names = read_optional(NAMES)?;
    Ok(handles
        .iter()
        .enumerate()
        .map(|(index, handle)| {
            names
                .lines()
                .find_map(|line| {
                    let mut fields = line.splitn(3, '\t');
                    (fields.next() == Some(user) && fields.next() == Some(handle))
                        .then(|| fields.next().unwrap_or_default().to_string())
                })
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| format!("Android device {}", index + 1))
        })
        .collect())
}

/// Lines as a file: one per line, no blank ones, empty when there are none.
fn lines_file<S: AsRef<str>>(lines: &[S]) -> String {
    lines
        .iter()
        .map(AsRef::as_ref)
        .filter(|line| !line.is_empty())
        .map(|line| format!("{line}\n"))
        .collect()
}

fn read_optional(path: &str) -> io::Result<String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error),
    }
}

fn connected_devices() -> io::Result<Vec<(String, String)>> {
    Ok(fs::read_to_string(format!("{STATE}/devices"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (id, label) = line.split_once('\t').unwrap_or((line, line));
            (!id.is_empty()).then(|| (id.to_string(), label.to_string()))
        })
        .collect())
}

fn select_connection(
    devices: &[(String, String)],
) -> Result<Option<(String, String)>, Box<dyn std::error::Error>> {
    if devices.len() <= 1 {
        return Ok(devices.first().cloned());
    }
    if !io::stdin().is_terminal() {
        return Err("several devices are connected; run in a terminal to choose one".into());
    }
    println!("Several devices are connected:");
    for (index, (_, label)) in devices.iter().enumerate() {
        println!("  {}  {label}", index + 1);
    }
    loop {
        print!("Device number: ");
        io::stdout().flush()?;
        let mut answer = String::new();
        if io::stdin().read_line(&mut answer)? == 0 {
            return Err("no device chosen".into()); // end of input (Ctrl-D)
        }
        if let Ok(index) = answer.trim().parse::<usize>()
            && let Some(device) = devices.get(index.saturating_sub(1))
        {
            return Ok(Some(device.clone()));
        }
    }
}

fn virtual_device() -> Option<String> {
    let output = Command::new("fido2-token").arg("-L").output().ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| line.contains("vendor=0x1209, product=0x7ab1"))
        .and_then(|line| line.split(':').next())
        .map(str::to_owned)
}

fn privileged(args: &[&str], input: Option<&[u8]>) -> Result<(), Box<dyn std::error::Error>> {
    let executable = env::current_exe()?;
    let mut command = if unsafe { libc::geteuid() } == 0 {
        Command::new(executable)
    } else {
        let mut command = Command::new("sudo");
        command.arg(executable);
        command
    };
    command.args(args);
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn()?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .ok_or("could not open privileged stdin")?
            .write_all(input)?;
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("privileged command failed with {status}").into())
    }
}

fn write_file(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("passkey-new-{}", std::process::id()));
    let _ = fs::remove_file(&temp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    file.write_all(data)?;
    file.sync_all()?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    fs::rename(temp, path)
}

fn current_user() -> Result<String, Box<dyn std::error::Error>> {
    let uid = unsafe { libc::getuid() };
    username(uid).ok_or_else(|| format!("no user for uid {uid}").into())
}

fn username(uid: libc::uid_t) -> Option<String> {
    let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16 * 1024];
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    (status == 0 && !result.is_null()).then(|| {
        unsafe { CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned()
    })
}

fn hostname() -> io::Result<String> {
    let mut buffer = [0_i8; 256];
    if unsafe { libc::gethostname(buffer.as_mut_ptr(), buffer.len()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .into_owned())
}

fn has_systemd() -> bool {
    Path::new("/run/systemd/system").is_dir() // what sd_booted(3) checks
}

/// Where PAM loads modules from: the directory holding pam_unix.so.
fn pam_module_dir() -> Option<PathBuf> {
    [
        "/usr/lib/security",
        "/usr/lib64/security",
        "/lib/security",
        "/lib64/security",
        "/usr/lib/x86_64-linux-gnu/security",
        "/lib/x86_64-linux-gnu/security",
        "/usr/lib/aarch64-linux-gnu/security",
        "/lib/aarch64-linux-gnu/security",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|dir| dir.join("pam_unix.so").is_file())
}

fn unix_takes_password() -> bool {
    ["system-auth", "common-auth", "password-auth"]
        .iter()
        .any(|file| {
            fs::read_to_string(format!("/etc/pam.d/{file}")).is_ok_and(|text| {
                text.lines().any(|line| {
                    !line.trim_start().starts_with('#')
                        && line.contains("pam_unix.so")
                        && (line.contains("try_first_pass") || line.contains("use_first_pass"))
                })
            })
        })
}

/// The package that provides something, by distribution family.
fn package(arch: &str, debian: &str, fedora: &str) -> String {
    let release = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let ids = release
        .lines()
        .filter_map(|line| {
            line.strip_prefix("ID=")
                .or_else(|| line.strip_prefix("ID_LIKE="))
        })
        .flat_map(|value| {
            value
                .trim_matches('"')
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let has = |id: &str| ids.iter().any(|value| value == id);
    if has("arch") {
        arch.into()
    } else if has("debian") || has("ubuntu") {
        debian.into()
    } else if has("fedora") || has("rhel") {
        fedora.into()
    } else {
        format!("{arch} (Arch) / {debian} (Debian) / {fedora} (Fedora)")
    }
}

/// What this computer needs, checked when it is used (not when installed):
/// missing requirements stop, missing transports only warn. Nothing is
/// installed; missing packages are named.
fn check_environment() -> Result<(), Box<dyn std::error::Error>> {
    let mut missing = Vec::new();
    let mut warnings = Vec::new();
    let pam_dir = pam_module_dir();
    if !Path::new("/etc/pam.d").is_dir() || pam_dir.is_none() {
        return Err("this system does not use Linux-PAM".into());
    }
    let pam_dir = pam_dir.unwrap_or_default();
    if !pam_dir.join("pam_u2f.so").is_file() {
        missing.push(format!(
            "pam_u2f.so: {}",
            package("pam-u2f", "libpam-u2f", "pam-u2f")
        ));
    }
    if !pam_dir.join("pam_passkey.so").is_file() {
        missing.push(format!(
            "pam_passkey.so is not in {} (install passkey with PAMDIR={})",
            pam_dir.display(),
            pam_dir.display()
        ));
    }
    if !program_exists("pamu2fcfg") {
        missing.push(format!(
            "pamu2fcfg: {}",
            package("pam-u2f", "pamu2fcfg", "pamu2fcfg")
        ));
    }
    if !program_exists("fido2-token") {
        missing.push(format!(
            "fido2-token: {}",
            package("libfido2", "fido2-tools", "fido2-tools")
        ));
    }
    if unsafe { libc::geteuid() } != 0 && !program_exists("sudo") {
        missing.push("sudo (or run passkey as root)".into());
    }
    let usb = program_exists("adb");
    if !usb {
        warnings.push(format!(
            "USB off: adb is missing ({})",
            package("android-tools", "adb", "android-tools")
        ));
    }
    let bluetooth = if has_systemd() {
        Command::new("systemctl")
            .args(["is-active", "--quiet", "bluetooth.service"])
            .status()
            .is_ok_and(|status| status.success())
    } else {
        program_exists("bluetoothd") || Path::new("/usr/lib/bluetooth/bluetoothd").is_file()
    };
    if !bluetooth {
        warnings.push(format!(
            "Bluetooth off: BlueZ is not running ({})",
            package("bluez", "bluez", "bluez")
        ));
    }
    if !has_systemd() {
        let user = current_user().unwrap_or_default();
        warnings.push(format!(
            "systemd is not running, so the service is not set up. Start it as root at boot with your init system:\n    PASSKEY_ADB_USER={user} {} daemon",
            env::current_exe().map(|path| path.display().to_string()).unwrap_or_else(|_| "passkey".into())
        ));
    }
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    if !missing.is_empty() {
        return Err(format!("missing, please install:\n  {}", missing.join("\n  ")).into());
    }
    if !usb && !bluetooth {
        return Err(
            "neither USB (adb) nor Bluetooth (BlueZ) is available: no way to reach the device"
                .into(),
        );
    }
    Ok(())
}

fn program_exists(program: &str) -> bool {
    env::var_os("PATH").is_some_and(|path| {
        env::split_paths(&path).any(|directory| directory.join(program).is_file())
    })
}

fn require_root() -> Result<(), Box<dyn std::error::Error>> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err("this internal command must run as root".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_lines_without_blanks() {
        assert_eq!(lines_file::<&str>(&[]), "");
        assert_eq!(lines_file(&["", "a:b", ""]), "a:b\n");
        assert_eq!(lines_file(&["a", "b".to_string().as_str()]), "a\nb\n");
    }

    #[test]
    fn recognizes_only_our_pam_lines() {
        assert!(is_ours(MARK));
        assert!(is_ours(
            "-auth sufficient pam_passkey.so authfile=/etc/passkey/u2f_keys nouserok"
        ));
        assert!(!is_ours("auth required pam_unix.so"));
    }
}
