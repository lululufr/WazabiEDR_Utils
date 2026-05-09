//! Generate an RFC 4122 v4 UUID using `BCryptGenRandom` (CNG).
//!
//! No `uuid` crate dependency: the call site only needs the canonical
//! 8-4-4-4-12 hex string, which is ~30 lines including the version /
//! variant bit fixup.

use std::ptr;

use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};

pub fn v4_string() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(format!("BCryptGenRandom failed: 0x{:x}", status as u32));
    }

    // RFC 4122 §4.4: set the version to 4 (random) in the high nibble
    // of byte 6, and set the IETF variant in the high two bits of
    // byte 8 (10xxxxxx).
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-\
         {:02x}{:02x}-\
         {:02x}{:02x}-\
         {:02x}{:02x}-\
         {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    ))
}
