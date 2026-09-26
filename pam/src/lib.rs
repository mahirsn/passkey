use libc::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;
const PAM_CONV_ERR: c_int = 19;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_TEXT_INFO: c_int = 4;
const PAM_AUTHTOK: c_int = 6;
const MAX_ARGS: usize = 32;
/// The `passkey` executable, set by the Makefile (PASSKEY_BIN).
const HELPER: &str = match option_env!("PASSKEY_BIN") {
    Some(path) => path,
    None => "/usr/bin/passkey",
};
const ASK_PARALLEL: Duration = Duration::from_secs(600);
const ASK_ON_EMPTY: Duration = Duration::from_secs(45);

#[repr(C)]
pub struct PamHandle(c_void);

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_user(
        handle: *mut PamHandle,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
    fn pam_prompt(
        handle: *mut PamHandle,
        style: c_int,
        response: *mut *mut c_char,
        format: *const c_char,
        ...
    ) -> c_int;
    fn pam_set_item(handle: *mut PamHandle, item: c_int, value: *const c_void) -> c_int;
}
// pam_info() is a macro in <security/pam_ext.h>, not an exported symbol; a
// module that links against it fails to load ("undefined symbol: pam_info").

struct Ask {
    child: Child,
    // The host (sudo, a display manager) may reap its children itself; a
    // pidfd still names this helper, a pid could name a reused one.
    pidfd: c_int,
    result: File,
    deadline: Instant,
}

impl Ask {
    fn start(timeout: Duration, helper: &str, user: &str, options: &[String]) -> io::Result<Self> {
        let mut pipe = [0; 2];
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let read_fd = pipe[0];
        let write_fd = pipe[1];
        let mut command = Command::new(helper);
        command
            .arg("pam-auth")
            .arg(user)
            .args(options)
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(write_fd, 3) < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                // A helper asked again after Enter is started while this
                // thread blocks all signals; it must not inherit that.
                let mut none = std::mem::zeroed::<libc::sigset_t>();
                libc::sigemptyset(&mut none);
                libc::pthread_sigmask(libc::SIG_SETMASK, &none, ptr::null_mut());
                Ok(())
            });
        }
        let child = command.spawn();
        unsafe { libc::close(write_fd) };
        let child = match child {
            Ok(child) => child,
            Err(error) => {
                unsafe { libc::close(read_fd) };
                return Err(error);
            }
        };
        // SAFETY: plain syscall on the pid just spawned; -1 on kernels without pidfd.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) } as c_int;
        Ok(Self {
            child,
            pidfd,
            result: unsafe { File::from_raw_fd(read_fd) },
            deadline: Instant::now() + timeout,
        })
    }

    fn answer(&mut self) -> io::Result<Option<bool>> {
        let mut poll = libc::pollfd {
            fd: self.result.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, 0) };
        if ready <= 0 {
            return Ok(None);
        }
        let mut byte = [0_u8; 1];
        Ok(Some(self.result.read(&mut byte)? == 1 && byte[0] == b'y'))
    }

    fn stop(&mut self) {
        if self.pidfd >= 0 {
            // SAFETY: pidfd is owned by this Ask and closed only here.
            unsafe {
                libc::syscall(libc::SYS_pidfd_send_signal, self.pidfd, libc::SIGKILL, ptr::null::<c_void>(), 0);
                libc::close(self.pidfd);
            }
            self.pidfd = -1;
        } else {
            let _ = self.child.kill();
        }
        let _ = self.child.wait(); // may fail if the host reaped it; harmless
    }
}

impl Drop for Ask {
    fn drop(&mut self) {
        self.stop();
    }
}

struct PromptResult {
    status: c_int,
    answer: usize,
}

#[unsafe(no_mangle)]
/// Linux-PAM authentication entry point.
///
/// # Safety
///
/// `handle` and `argv` must be valid for the duration of this call and follow
/// the Linux-PAM module ABI.
pub unsafe extern "C" fn pam_sm_authenticate(
    handle: *mut PamHandle,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    std::panic::catch_unwind(|| unsafe { authenticate(handle, argc, argv) }).unwrap_or(PAM_IGNORE)
}

unsafe fn authenticate(handle: *mut PamHandle, argc: c_int, argv: *const *const c_char) -> c_int {
    if handle.is_null() || argc < 0 || (argc > 0 && argv.is_null()) {
        return PAM_IGNORE;
    }
    let mut on_empty = false;
    let mut helper = HELPER.to_string();
    let mut authfile = None;
    let mut options = Vec::new();
    for index in 0..(argc as usize).min(MAX_ARGS) {
        let value = unsafe { CStr::from_ptr(*argv.add(index)) }
            .to_string_lossy()
            .into_owned();
        match value.as_str() {
            "mode=on-empty" => on_empty = true,
            "mode=parallel" => {}
            _ if value.starts_with("helper=") => helper = value[7..].to_string(),
            _ => {
                if let Some(value) = value.strip_prefix("authfile=") {
                    authfile = Some(value.to_string());
                }
                options.push(value);
            }
        }
    }
    let Some(authfile) = authfile else {
        return PAM_IGNORE;
    };
    let mut user_ptr = ptr::null();
    if unsafe { pam_get_user(handle, &mut user_ptr, ptr::null()) } != PAM_SUCCESS
        || user_ptr.is_null()
    {
        return PAM_IGNORE;
    }
    let user = unsafe { CStr::from_ptr(user_ptr) }
        .to_string_lossy()
        .into_owned();
    if !device_present() || !user_registered(&authfile, &user) || !is_executable(&helper) {
        return PAM_IGNORE;
    }

    let timeout = if on_empty { ASK_ON_EMPTY } else { ASK_PARALLEL };
    let mut ask = (!on_empty)
        .then(|| Ask::start(timeout, &helper, &user, &options).ok())
        .flatten();
    let mut tries = usize::from(ask.is_some());

    let prompt = if on_empty {
        c"Password: "
    } else {
        c"Password (or confirm on your device): "
    };
    let (sender, receiver) = mpsc::channel();
    let handle_address = handle as usize;
    let prompt_thread = thread::spawn(move || {
        let mut answer = ptr::null_mut();
        let status = unsafe {
            pam_prompt(
                handle_address as *mut PamHandle,
                PAM_PROMPT_ECHO_OFF,
                &mut answer,
                c"%s".as_ptr(),
                prompt.as_ptr(),
            )
        };
        let result = PromptResult {
            status,
            answer: answer as usize,
        };
        if let Err(error) = sender.send(result) {
            wipe(error.0.answer as *mut c_char);
        }
    });
    let mut prompt_thread = Some(prompt_thread);
    let mut prompting = true;
    let mut result = PAM_IGNORE;

    // Signals go to the prompt thread (started above, with the host's mask),
    // so ^C at the prompt interrupts it as without this module.
    let mut old_mask = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    unsafe {
        let mut all = std::mem::zeroed::<libc::sigset_t>();
        libc::sigfillset(&mut all);
        libc::pthread_sigmask(libc::SIG_BLOCK, &all, &mut old_mask);
    }

    loop {
        if prompting && let Ok(prompt_result) = receiver.try_recv() {
            prompting = false;
            if let Some(thread) = prompt_thread.take() {
                let _ = thread.join();
            }
            let answer = prompt_result.answer as *mut c_char;
            if prompt_result.status != PAM_SUCCESS || answer.is_null() {
                result = if prompt_result.status == PAM_SUCCESS {
                    PAM_CONV_ERR
                } else {
                    prompt_result.status
                };
                wipe(answer);
                break;
            }
            let empty = unsafe { *answer == 0 };
            if !empty {
                let status = unsafe { pam_set_item(handle, PAM_AUTHTOK, answer.cast()) };
                wipe(answer);
                result = if status == PAM_SUCCESS {
                    PAM_IGNORE
                } else {
                    status
                };
                break;
            }
            wipe(answer);
            if ask.is_none() && tries < 3 {
                unsafe {
                    pam_prompt(
                        handle,
                        PAM_TEXT_INFO,
                        ptr::null_mut(),
                        c"%s".as_ptr(),
                        c"Confirm with your fingerprint on your device.".as_ptr(),
                    );
                }
                ask = Ask::start(timeout, &helper, &user, &options).ok();
                tries += usize::from(ask.is_some());
            }
            if ask.is_none() {
                break;
            }
        }

        if let Some(active) = ask.as_mut() {
            match active.answer() {
                Ok(Some(approved)) => {
                    ask = None;
                    if approved {
                        result = PAM_SUCCESS;
                        if prompting {
                            end_tty_prompt();
                            if let Ok(prompt_result) = receiver.recv_timeout(Duration::from_secs(1))
                            {
                                wipe(prompt_result.answer as *mut c_char);
                                if let Some(thread) = prompt_thread.take() {
                                    let _ = thread.join();
                                }
                            }
                        }
                        break;
                    }
                    if !prompting {
                        break;
                    }
                }
                Ok(None) if Instant::now() >= active.deadline => {
                    ask = None;
                    if !prompting {
                        break;
                    }
                }
                Err(_) => ask = None,
                _ => {}
            }
        } else if !prompting {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old_mask, ptr::null_mut()) };
    drop(ask);
    drop(prompt_thread);
    result
}

fn device_present() -> bool {
    let Ok(entries) = fs::read_dir("/sys/class/hidraw") else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        fs::read_to_string(entry.path().join("device/uevent")).is_ok_and(|text| {
            text.lines()
                .any(|line| line == "HID_ID=0003:00001209:00007AB1")
        })
    })
}

fn user_registered(path: &str, user: &str) -> bool {
    fs::read_to_string(path).is_ok_and(|text| {
        text.lines().any(|line| {
            line.strip_prefix(user)
                .and_then(|line| line.strip_prefix(':'))
                .is_some_and(|credentials| !credentials.is_empty())
        })
    })
}

fn is_executable(path: &str) -> bool {
    CString::new(path).is_ok_and(|path| unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 })
}

fn end_tty_prompt() {
    let fd = unsafe {
        libc::open(
            c"/dev/tty".as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return;
    }
    let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(fd, &mut termios) } == 0 && termios.c_lflag & libc::ECHO == 0 {
        let mut newline = b'\n';
        unsafe { libc::ioctl(fd, libc::TIOCSTI, &mut newline) };
    }
    unsafe { libc::close(fd) };
}

fn wipe(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    let length = unsafe { libc::strlen(value) };
    unsafe {
        libc::explicit_bzero(value.cast(), length);
        libc::free(value.cast());
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _handle: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_requires_a_nonempty_credential() {
        let path = std::env::temp_dir().join(format!("passkey-pam-test-{}", std::process::id()));
        fs::write(&path, "alice:key,data\nbob:\n").unwrap();
        assert!(user_registered(path.to_str().unwrap(), "alice"));
        assert!(!user_registered(path.to_str().unwrap(), "bob"));
        assert!(!user_registered(path.to_str().unwrap(), "ali"));
        fs::remove_file(path).unwrap();
    }
}
