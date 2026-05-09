//! SHA-256 over a file via Windows BCrypt (CNG).
//!
//! Mirrors the routine in `WazabiEDR_Agent::plugin::identity` so an
//! enrolled hash is computed the same way the agent will compute it at
//! runtime. Kept dependency-free — no `sha2` crate.

use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GENERIC_READ, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE, BCRYPT_SHA256_ALGORITHM, BCryptCloseAlgorithmProvider,
    BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash, BCryptHashData,
    BCryptOpenAlgorithmProvider,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, OPEN_EXISTING, ReadFile,
};

pub fn sha256_file_hex(path: &std::path::Path) -> std::io::Result<String> {
    let wide: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let h = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        return Err(std::io::Error::from_raw_os_error(err as i32));
    }

    let result = (|| -> std::io::Result<String> {
        let mut alg: BCRYPT_ALG_HANDLE = ptr::null_mut();
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut alg, BCRYPT_SHA256_ALGORITHM, ptr::null(), 0)
        };
        if status != 0 {
            return Err(std::io::Error::other(format!(
                "BCryptOpenAlgorithmProvider failed: 0x{:x}",
                status as u32
            )));
        }

        let mut hash: BCRYPT_HASH_HANDLE = ptr::null_mut();
        let status =
            unsafe { BCryptCreateHash(alg, &mut hash, ptr::null_mut(), 0, ptr::null(), 0, 0) };
        if status != 0 {
            unsafe { BCryptCloseAlgorithmProvider(alg, 0) };
            return Err(std::io::Error::other(format!(
                "BCryptCreateHash failed: 0x{:x}",
                status as u32
            )));
        }

        let mut buf = [0u8; 64 * 1024];
        loop {
            let mut read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    h,
                    buf.as_mut_ptr() as *mut _,
                    buf.len() as u32,
                    &mut read,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                unsafe {
                    BCryptDestroyHash(hash);
                    BCryptCloseAlgorithmProvider(alg, 0);
                }
                return Err(std::io::Error::from_raw_os_error(err as i32));
            }
            if read == 0 {
                break;
            }
            let status = unsafe { BCryptHashData(hash, buf.as_ptr(), read, 0) };
            if status != 0 {
                unsafe {
                    BCryptDestroyHash(hash);
                    BCryptCloseAlgorithmProvider(alg, 0);
                }
                return Err(std::io::Error::other(format!(
                    "BCryptHashData failed: 0x{:x}",
                    status as u32
                )));
            }
        }

        let mut digest = [0u8; 32];
        let status =
            unsafe { BCryptFinishHash(hash, digest.as_mut_ptr(), digest.len() as u32, 0) };
        unsafe {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(alg, 0);
        }
        if status != 0 {
            return Err(std::io::Error::other(format!(
                "BCryptFinishHash failed: 0x{:x}",
                status as u32
            )));
        }

        let mut hex = String::with_capacity(64);
        for b in digest {
            hex.push_str(&format!("{:02x}", b));
        }
        Ok(hex)
    })();

    unsafe { CloseHandle(h) };
    result
}
