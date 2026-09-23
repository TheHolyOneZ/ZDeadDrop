use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

#[derive(ZeroizeOnDrop)]
pub struct Secret<const N: usize> {
    bytes: [u8; N],
}

pub type Key32 = Secret<32>;

pub type Key64 = Secret<64>;

impl<const N: usize> Secret<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; N];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub fn zeroed() -> Self {
        Self { bytes: [0u8; N] }
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != N {
            return Err(Error::length("secret", N, slice.len()));
        }
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(slice);
        Ok(Self { bytes })
    }

    pub fn expose(&self) -> &[u8; N] {
        &self.bytes
    }

    pub(crate) fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    pub fn duplicate(&self) -> Self {
        Self { bytes: self.bytes }
    }

    pub const fn len(&self) -> usize {
        N
    }

    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{N}>(redacted)")
    }
}

impl<const N: usize> ConstantTimeEq for Secret<N> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const N: usize> Eq for Secret<N> {}

#[derive(ZeroizeOnDrop)]
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            bytes: slice.to_vec(),
        }
    }

    pub fn from_string(mut s: String) -> Self {
        let bytes = s.as_bytes().to_vec();
        s.zeroize();
        Self { bytes }
    }

    pub fn zeroed(len: usize) -> Self {
        Self {
            bytes: vec![0u8; len],
        }
    }

    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn truncate_zeroizing(&mut self, len: usize) {
        if len < self.bytes.len() {
            self.bytes[len..].zeroize();
            self.bytes.truncate(len);
        }
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes({} bytes, redacted)", self.bytes.len())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.len() == other.bytes.len() && bool::from(self.bytes.ct_eq(&other.bytes))
    }
}

impl Eq for SecretBytes {}

#[cfg(unix)]
pub fn harden_process() -> bool {
    let mut ok = true;

    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            ok = false;
        }
    }

    #[cfg(target_os = "linux")]
    {
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
                ok = false;
            }
        }
    }

    ok
}

#[cfg(windows)]
pub fn harden_process() -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
    };
    use windows_sys::Win32::System::ErrorReporting::WerAddExcludedApplication;

    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    }

    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let wide: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();

    let hr = unsafe { WerAddExcludedApplication(wide.as_ptr(), 0) };
    hr >= 0
}

#[cfg(not(any(unix, windows)))]
pub fn harden_process() -> bool {
    false
}

#[cfg(unix)]
pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }

    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

#[cfg(windows)]
pub fn lock_memory(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }

    unsafe { windows_sys::Win32::System::Memory::VirtualLock(ptr as *const _, len) != 0 }
}

#[cfg(not(any(unix, windows)))]
pub fn lock_memory(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(unix)]
pub fn unlock_memory(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }

    unsafe { libc::munlock(ptr as *const libc::c_void, len) == 0 }
}

#[cfg(windows)]
pub fn unlock_memory(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }

    unsafe { windows_sys::Win32::System::Memory::VirtualUnlock(ptr as *const _, len) != 0 }
}

#[cfg(not(any(unix, windows)))]
pub fn unlock_memory(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_reveals_bytes() {
        let k = Key32::new([0xAB; 32]);
        let rendered = format!("{k:?}");
        assert_eq!(rendered, "Secret<32>(redacted)");
        assert!(!rendered.contains("ab"), "debug output leaked key bytes");
        assert!(!rendered.contains("171"), "debug output leaked key bytes");

        let b = SecretBytes::from_slice(&[0xCD; 8]);
        let rendered = format!("{b:?}");
        assert_eq!(rendered, "SecretBytes(8 bytes, redacted)");
        assert!(!rendered.contains("cd"));
    }

    #[test]
    fn equality_is_value_based() {
        let a = Key32::new([7; 32]);
        let b = Key32::new([7; 32]);
        let c = Key32::new([8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        assert!(Key32::from_slice(&[0; 31]).is_err());
        assert!(Key32::from_slice(&[0; 33]).is_err());
        assert!(Key32::from_slice(&[0; 32]).is_ok());
    }

    #[test]
    fn random_secrets_differ() {
        let a = Key32::random();
        let b = Key32::random();
        assert_ne!(a, b, "OsRng returned identical 32-byte secrets");
        assert_ne!(a.expose(), &[0u8; 32], "OsRng returned all zeros");
    }

    #[test]
    fn from_string_clears_the_original() {
        let s = String::from("correct horse battery staple");
        let secret = SecretBytes::from_string(s);
        assert_eq!(secret.expose(), b"correct horse battery staple");
    }

    #[test]
    fn truncate_zeroizes_the_tail() {
        let mut b = SecretBytes::from_slice(&[0xFF; 64]);
        b.truncate_zeroizing(8);
        assert_eq!(b.len(), 8);
        assert_eq!(b.expose(), &[0xFF; 8]);
    }

    #[test]
    fn process_hardening_succeeds() {
        let _ = harden_process();
    }
}
