//! Windows: the user a process runs as, so the pipe can be owner-only and a
//! client only talks to a daemon of its own user.

#![allow(unsafe_code)]

use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// A handle closed on drop.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from OpenProcess / OpenProcessToken
            // and is closed exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// The string SID (`S-1-5-21-…`) of the user `process` runs as.
fn token_user_sid(process: HANDLE) -> io::Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `process` is a valid process handle; `token` is an out-pointer.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Owned(token);
    let mut len = 0u32;
    // SAFETY: a size query (null buffer, zero length) that only writes `len`.
    unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    // u64 storage keeps the TOKEN_USER (pointer-sized fields) aligned.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` holds at least `len` writable, aligned bytes.
    if unsafe { GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call above filled `buf` with a TOKEN_USER whose SID points
    // into `buf`, which outlives every use of `sid` below.
    let sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let mut wide: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is valid; `wide` receives a LocalAlloc'd string.
    if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `wide` is a NUL-terminated UTF-16 string from the call above;
    // it is read once and then freed with LocalFree as documented.
    let s = unsafe {
        let mut n = 0;
        while *wide.add(n) != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(wide, n));
        LocalFree(wide.cast());
        s
    };
    Ok(s)
}

/// The SID of the user running this process.
pub(crate) fn current_user_sid() -> io::Result<String> {
    // SAFETY: returns a pseudo-handle that needs no closing.
    token_user_sid(unsafe { GetCurrentProcess() })
}

/// The SID of the user running process `pid`.
pub(crate) fn process_user_sid(pid: u32) -> io::Result<String> {
    // SAFETY: OpenProcess has no preconditions; it returns null on failure.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    let h = Owned(h);
    token_user_sid(h.0)
}

/// SDDL for a pipe only this user (and SYSTEM) may open, in any way.
pub(crate) fn owner_only_sddl(sid: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_runs_as_the_current_user() {
        let me = current_user_sid().unwrap();
        assert!(me.starts_with("S-1-"), "{me}");
        assert_eq!(process_user_sid(std::process::id()).unwrap(), me);
        let sddl = widestring::U16CString::from_str(owner_only_sddl(&me)).unwrap();
        interprocess::os::windows::security_descriptor::SecurityDescriptor::deserialize(&sddl)
            .unwrap();
    }
}
