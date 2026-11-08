//! `passkey pam-auth USER [pam_u2f options...]`, run by the PAM module: asks
//! every connected device at once and writes "y" to fd 3 when one of them
//! signs with a key registered for USER, "n" when the user refuses there.
//!
//! pam_u2f, which this used to run, tries the user's keys one after another,
//! so a second device was only asked after the first had refused or timed
//! out. Here one request carries all of them; the daemon hands it to every
//! device, the first approval answers, and the signature is checked against
//! the key it names.

use libc::{c_char, c_int, c_void, size_t};
use std::ffi::{CStr, CString};
use std::fs;

const FIDO_OK: c_int = 0;
const FIDO_ERR_OPERATION_DENIED: c_int = 0x27;
const FIDO_OPT_FALSE: c_int = 1;
const FIDO_OPT_TRUE: c_int = 2;
const COSE_ES256: c_int = -7;
// The daemon's virtual key (daemon.rs, create_uhid).
const VENDOR: i16 = 0x1209;
const PRODUCT: i16 = 0x7ab1;

#[repr(C)]
struct DevInfo(c_void);
#[repr(C)]
struct Dev(c_void);
#[repr(C)]
struct Assert(c_void);
#[repr(C)]
struct Es256Pk(c_void);

#[link(name = "fido2")]
unsafe extern "C" {
    fn fido_init(flags: c_int);
    fn fido_dev_info_new(n: size_t) -> *mut DevInfo;
    fn fido_dev_info_free(list: *mut *mut DevInfo, n: size_t);
    fn fido_dev_info_manifest(list: *mut DevInfo, max: size_t, found: *mut size_t) -> c_int;
    fn fido_dev_info_ptr(list: *const DevInfo, index: size_t) -> *const DevInfo;
    fn fido_dev_info_path(info: *const DevInfo) -> *const c_char;
    fn fido_dev_info_vendor(info: *const DevInfo) -> i16;
    fn fido_dev_info_product(info: *const DevInfo) -> i16;
    fn fido_dev_new() -> *mut Dev;
    fn fido_dev_open(dev: *mut Dev, path: *const c_char) -> c_int;
    fn fido_dev_close(dev: *mut Dev) -> c_int;
    fn fido_dev_free(dev: *mut *mut Dev);
    fn fido_dev_get_assert(dev: *mut Dev, assert: *mut Assert, pin: *const c_char) -> c_int;
    fn fido_assert_new() -> *mut Assert;
    fn fido_assert_free(assert: *mut *mut Assert);
    fn fido_assert_set_rp(assert: *mut Assert, id: *const c_char) -> c_int;
    fn fido_assert_set_clientdata_hash(assert: *mut Assert, hash: *const u8, len: size_t) -> c_int;
    fn fido_assert_allow_cred(assert: *mut Assert, id: *const u8, len: size_t) -> c_int;
    fn fido_assert_set_up(assert: *mut Assert, up: c_int) -> c_int;
    fn fido_assert_set_uv(assert: *mut Assert, uv: c_int) -> c_int;
    fn fido_assert_count(assert: *const Assert) -> size_t;
    fn fido_assert_id_ptr(assert: *const Assert, index: size_t) -> *const u8;
    fn fido_assert_id_len(assert: *const Assert, index: size_t) -> size_t;
    fn fido_assert_verify(
        assert: *const Assert,
        index: size_t,
        cose_alg: c_int,
        pk: *const c_void,
    ) -> c_int;
    fn es256_pk_new() -> *mut Es256Pk;
    fn es256_pk_free(pk: *mut *mut Es256Pk);
    fn es256_pk_from_ptr(pk: *mut Es256Pk, data: *const c_void, len: size_t) -> c_int;
}

#[derive(Debug, PartialEq)]
struct Credential {
    id: Vec<u8>,
    key: Vec<u8>,
    verification: bool,
}

pub fn run(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let Some(user) = args.first() else {
        return Err("usage: passkey pam-auth USER [pam_u2f options...]".into());
    };
    let mut authfile = None;
    let mut origin = None;
    let mut verification = false;
    for option in &args[1..] {
        if let Some(value) = option.strip_prefix("authfile=") {
            authfile = Some(value);
        } else if let Some(value) = option.strip_prefix("origin=") {
            origin = Some(value);
        } else if option == "userverification=1" {
            verification = true;
        }
    }
    let authfile = authfile.ok_or("no authfile= option")?;
    let origin = CString::new(origin.ok_or("no origin= option")?)?;
    let credentials = credentials(&fs::read_to_string(authfile)?, user);
    if credentials.is_empty() {
        return Err(format!("no keys registered for {user}").into());
    }
    verification |= credentials.iter().any(|credential| credential.verification);

    let device = Device::open()?;
    // A request that needs no approval first: the daemon learns which devices
    // hold one of these keys and then asks all of those together.
    if let Ok(probe) = Assertion::new(&origin, &credentials) {
        probe.set_up(FIDO_OPT_FALSE);
        let _ = device.get(&probe);
    }
    let assertion = Assertion::new(&origin, &credentials)?;
    assertion.set_up(FIDO_OPT_TRUE);
    if verification {
        assertion.set_uv(FIDO_OPT_TRUE);
    }
    match device.get(&assertion) {
        FIDO_OK => {}
        FIDO_ERR_OPERATION_DENIED => {
            // Tells the PAM module the user said no, so it does not ask again.
            unsafe { libc::write(3, b"n".as_ptr().cast(), 1) };
            return Err("fingerprint was refused".into());
        }
        _ => return Err("fingerprint was not approved".into()),
    }
    if !assertion.verify(&credentials) {
        return Err("the device's signature did not verify".into());
    }
    if unsafe { libc::write(3, b"y".as_ptr().cast(), 1) } != 1 {
        return Err("PAM result pipe is closed".into());
    }
    Ok(())
}

/// The user's keys from a pam_u2f authfile line:
/// `user:handle,public key,es256,+presence+verification:...`, base64.
/// Only ES256 keys with a handle; the app makes no other kind.
fn credentials(authfile: &str, user: &str) -> Vec<Credential> {
    authfile
        .lines()
        .filter_map(|line| line.strip_prefix(user)?.strip_prefix(':'))
        .flat_map(|rest| rest.split(':'))
        .filter_map(|entry| {
            let mut fields = entry.split(',');
            let id = base64(fields.next()?)?;
            let key = base64(fields.next()?)?;
            if fields.next()? != "es256" || id.is_empty() {
                return None;
            }
            let verification = fields.next().unwrap_or("").contains("+verification");
            Some(Credential {
                id,
                key,
                verification,
            })
        })
        .collect()
}

fn base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut bits, mut count) = (0_u32, 0);
    for byte in text.trim_end_matches('=').bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Some(out)
}

struct Device(*mut Dev);

impl Device {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        const MAX: size_t = 64;
        unsafe {
            fido_init(0);
            let mut list = fido_dev_info_new(MAX);
            if list.is_null() {
                return Err("out of memory".into());
            }
            let mut found = 0;
            let mut path = None;
            if fido_dev_info_manifest(list, MAX, &mut found) == FIDO_OK {
                path = (0..found)
                    .map(|index| fido_dev_info_ptr(list, index))
                    .find(|info| {
                        fido_dev_info_vendor(*info) == VENDOR
                            && fido_dev_info_product(*info) == PRODUCT
                    })
                    .map(|info| CStr::from_ptr(fido_dev_info_path(info)).to_owned());
            }
            fido_dev_info_free(&mut list, MAX);
            let path = path.ok_or("no device connected")?;
            let device = fido_dev_new();
            if device.is_null() {
                return Err("out of memory".into());
            }
            let device = Self(device);
            if fido_dev_open(device.0, path.as_ptr()) != FIDO_OK {
                return Err("the passkey device could not be opened".into());
            }
            Ok(device)
        }
    }

    fn get(&self, assertion: &Assertion) -> c_int {
        unsafe { fido_dev_get_assert(self.0, assertion.0, std::ptr::null()) }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            fido_dev_close(self.0);
            fido_dev_free(&mut self.0);
        }
    }
}

struct Assertion(*mut Assert);

impl Assertion {
    fn new(origin: &CStr, credentials: &[Credential]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut hash = [0_u8; 32];
        if unsafe { libc::getrandom(hash.as_mut_ptr().cast(), hash.len(), 0) } != 32 {
            return Err("no randomness".into());
        }
        let assertion = Self(unsafe { fido_assert_new() });
        if assertion.0.is_null() {
            return Err("out of memory".into());
        }
        unsafe {
            if fido_assert_set_rp(assertion.0, origin.as_ptr()) != FIDO_OK
                || fido_assert_set_clientdata_hash(assertion.0, hash.as_ptr(), hash.len())
                    != FIDO_OK
            {
                return Err("could not build the request".into());
            }
            for credential in credentials {
                if fido_assert_allow_cred(assertion.0, credential.id.as_ptr(), credential.id.len())
                    != FIDO_OK
                {
                    return Err("could not build the request".into());
                }
            }
        }
        Ok(assertion)
    }

    fn set_up(&self, value: c_int) {
        unsafe { fido_assert_set_up(self.0, value) };
    }

    fn set_uv(&self, value: c_int) {
        unsafe { fido_assert_set_uv(self.0, value) };
    }

    /// The signature checks out against the key it names, and the flags show
    /// the presence and verification asked for (libfido2 checks those).
    fn verify(&self, credentials: &[Credential]) -> bool {
        unsafe {
            if fido_assert_count(self.0) != 1 {
                return false;
            }
            let id = fido_assert_id_ptr(self.0, 0);
            if id.is_null() {
                return false;
            }
            let id = std::slice::from_raw_parts(id, fido_assert_id_len(self.0, 0));
            let Some(credential) = credentials.iter().find(|credential| credential.id == id) else {
                return false;
            };
            let mut key = es256_pk_new();
            if key.is_null() {
                return false;
            }
            let verified =
                es256_pk_from_ptr(key, credential.key.as_ptr().cast(), credential.key.len())
                    == FIDO_OK
                    && fido_assert_verify(self.0, 0, COSE_ES256, key.cast()) == FIDO_OK;
            es256_pk_free(&mut key);
            verified
        }
    }
}

impl Drop for Assertion {
    fn drop(&mut self) {
        unsafe { fido_assert_free(&mut self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base64() {
        assert_eq!(base64("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64("aGVsbG8").unwrap(), b"hello");
        assert_eq!(base64("+/8=").unwrap(), [0xfb, 0xff]);
        assert!(base64("a*b").is_none());
    }

    #[test]
    fn reads_every_key_of_the_user() {
        let file = "other:b3RoZXI=,a2V5,es256,+presence\n\
                    me:aWQx,a2V5MQ==,es256,+presence+verification:aWQy,a2V5Mg==,es256,+presence\
                    :aWQz,a2V5Mw==,eddsa,+presence\n\
                    meeting:aWQ0,a2V5NA==,es256,+presence\n";
        let found = credentials(file, "me");
        assert_eq!(
            found,
            vec![
                Credential {
                    id: b"id1".to_vec(),
                    key: b"key1".to_vec(),
                    verification: true
                },
                Credential {
                    id: b"id2".to_vec(),
                    key: b"key2".to_vec(),
                    verification: false
                },
            ]
        );
        assert!(credentials(file, "nobody").is_empty());
    }
}
