use libc::{c_char, c_int, c_void};
use std::ffi::{CStr, CString};
use std::ptr;

const PAM_SUCCESS: c_int = 0;
const PAM_CONV_ERR: c_int = 19;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_SILENT: c_int = 0x8000;

#[repr(C)]
struct PamHandle(c_void);

#[repr(C)]
struct PamMessage {
    style: c_int,
    message: *const c_char,
}

#[repr(C)]
struct PamResponse {
    response: *mut c_char,
    code: c_int,
}

#[repr(C)]
struct PamConv {
    callback: Option<
        unsafe extern "C" fn(
            c_int,
            *mut *const PamMessage,
            *mut *mut PamResponse,
            *mut c_void,
        ) -> c_int,
    >,
    data: *mut c_void,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        handle: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_end(handle: *mut PamHandle, status: c_int) -> c_int;
}

type Authenticate =
    unsafe extern "C" fn(*mut PamHandle, c_int, c_int, *const *const c_char) -> c_int;

unsafe extern "C" fn conversation(
    count: c_int,
    messages: *mut *const PamMessage,
    responses: *mut *mut PamResponse,
    _: *mut c_void,
) -> c_int {
    for index in 0..count {
        // SAFETY: Linux-PAM owns an array containing `count` message pointers.
        let message = unsafe { &**messages.add(index as usize) };
        if matches!(message.style, PAM_PROMPT_ECHO_OFF | PAM_PROMPT_ECHO_ON) {
            return PAM_CONV_ERR;
        }
    }
    // pam_u2f only emits informational messages through this conversation.
    unsafe { *responses = ptr::null_mut() };
    PAM_SUCCESS
}

pub fn run(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let Some(user) = args.first() else {
        return Err("usage: passkey pam-auth USER [pam_u2f options...]".into());
    };
    let user = CString::new(user.as_str())?;
    let options: Vec<CString> = args[1..]
        .iter()
        .map(|value| CString::new(value.as_str()))
        .collect::<Result<_, _>>()?;
    let option_ptrs: Vec<*const c_char> = options.iter().map(|value| value.as_ptr()).collect();

    let (library, authenticate) = load_pam_u2f().ok_or("pam_u2f.so not found")?;
    let conv = PamConv {
        callback: Some(conversation),
        data: ptr::null_mut(),
    };
    let mut handle = ptr::null_mut();
    let service = c"passkey-u2f";
    // SAFETY: all pointers remain valid for the complete PAM transaction.
    let started = unsafe { pam_start(service.as_ptr(), user.as_ptr(), &conv, &mut handle) };
    if started != PAM_SUCCESS {
        unsafe { libc::dlclose(library) };
        return Err("pam_start failed".into());
    }
    let status = unsafe {
        authenticate(
            handle,
            PAM_SILENT,
            option_ptrs.len() as c_int,
            option_ptrs.as_ptr(),
        )
    };
    unsafe {
        pam_end(handle, status);
        libc::dlclose(library);
    }
    if status != PAM_SUCCESS {
        return Err("fingerprint was not approved".into());
    }
    if unsafe { libc::write(3, b"y".as_ptr().cast(), 1) } != 1 {
        return Err("PAM result pipe is closed".into());
    }
    Ok(())
}

fn load_pam_u2f() -> Option<(*mut c_void, Authenticate)> {
    const DIRS: &[&str] = &[
        "/usr/lib/security",
        "/lib/security",
        "/usr/lib64/security",
        "/lib64/security",
        "/usr/lib/x86_64-linux-gnu/security",
        "/lib/x86_64-linux-gnu/security",
        "/usr/lib/aarch64-linux-gnu/security",
        "/lib/aarch64-linux-gnu/security",
    ];
    for directory in DIRS {
        let path = CString::new(format!("{directory}/pam_u2f.so")).ok()?;
        let library = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if library.is_null() {
            continue;
        }
        let symbol = unsafe { libc::dlsym(library, c"pam_sm_authenticate".as_ptr()) };
        if symbol.is_null() {
            unsafe { libc::dlclose(library) };
            continue;
        }
        // SAFETY: pam_u2f exports pam_sm_authenticate with Linux-PAM's ABI.
        let function = unsafe { std::mem::transmute::<*mut c_void, Authenticate>(symbol) };
        return Some((library, function));
    }
    None
}

#[allow(dead_code)]
fn _message(message: *const c_char) -> String {
    if message.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned()
    }
}
