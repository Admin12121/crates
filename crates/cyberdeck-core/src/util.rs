//! Small shared primitives: hex codecs, byte order helpers and timestamps.

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::DeckError;

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Lowercase/uppercase-insensitive hex encoder (upper case output).
pub fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push(HEX_UPPER[(byte >> 4) as usize] as char);
        out.push(HEX_UPPER[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Colon-separated byte dump (`AA:BB:CC`).
pub fn hex_join(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 3);
    for (idx, byte) in data.iter().enumerate() {
        if idx > 0 {
            out.push(':');
        }
        out.push(HEX_UPPER[(byte >> 4) as usize] as char);
        out.push(HEX_UPPER[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Single hex digit value, exposed for MAC/WPS/script parsing.
pub fn hex_val_checked(byte: u8) -> Option<u8> {
    hex_val(byte)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode hex into `out`, returning the number of bytes written.
pub fn hex_decode(text: &str, out: &mut [u8]) -> Result<usize, DeckError> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(DeckError::InvalidInput {
            reason: "hex string has an odd length",
        });
    }
    let count = bytes.len() / 2;
    if count > out.len() {
        return Err(DeckError::InvalidInput {
            reason: "hex string does not fit the destination buffer",
        });
    }
    for i in 0..count {
        let hi = hex_val(bytes[i * 2]).ok_or(DeckError::InvalidInput {
            reason: "hex string contains a non-hex character",
        })?;
        let lo = hex_val(bytes[i * 2 + 1]).ok_or(DeckError::InvalidInput {
            reason: "hex string contains a non-hex character",
        })?;
        out[i] = (hi << 4) | lo;
    }
    Ok(count)
}

/// Decode hex into a Vec (test fixtures, script constants).
pub fn hex_to_vec(text: &str) -> Result<Vec<u8>, DeckError> {
    let mut out = alloc::vec![0u8; text.len() / 2];
    let n = hex_decode(text, &mut out)?;
    out.truncate(n);
    Ok(out)
}

/// Escape arbitrary bytes as a Rust-free printable string for logs/CSV.
pub fn printable(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());
    for &b in data {
        if b.is_ascii_graphic() || b == b' ' {
            out.push(b as char);
        } else {
            out.push('.');
        }
    }
    out
}

pub fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes([
        *data.get(offset)?,
        *data.get(offset + 1)?,
    ]))
}

pub fn read_u16_be(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *data.get(offset)?,
        *data.get(offset + 1)?,
    ]))
}

pub fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *data.get(offset)?,
        *data.get(offset + 1)?,
        *data.get(offset + 2)?,
        *data.get(offset + 3)?,
    ]))
}

pub fn write_u16_le(out: &mut [u8], offset: usize, value: u16) {
    let bytes = value.to_le_bytes();
    out[offset] = bytes[0];
    out[offset + 1] = bytes[1];
}

pub fn write_u16_be(out: &mut [u8], offset: usize, value: u16) {
    let bytes = value.to_be_bytes();
    out[offset] = bytes[0];
    out[offset + 1] = bytes[1];
}

pub fn write_u32_le(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub fn write_u32_be(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

pub fn write_u64_be(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

/// Constant-time byte comparison (MIC/PMKID checks must not leak via timing).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let data = [0x00, 0x1f, 0xab, 0xff];
        let text = hex_encode(&data);
        assert_eq!(text, "001FABFF");
        let mut out = [0u8; 4];
        assert_eq!(hex_decode(&text, &mut out).unwrap(), 4);
        assert_eq!(out, data);
        assert_eq!(hex_join(&data), "00:1F:AB:FF");
        assert_eq!(hex_to_vec("deadbeef").unwrap(), [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_rejects_bad_input() {
        let mut out = [0u8; 4];
        assert!(hex_decode("abc", &mut out).is_err());
        assert!(hex_decode("zz", &mut out).is_err());
        assert!(hex_decode("0011223344", &mut out).is_err());
    }

    #[test]
    fn constant_time_eq_matches_semantics() {
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!ct_eq(&[1, 2], &[1, 2, 3]));
    }

    #[test]
    fn printable_hides_control_bytes() {
        assert_eq!(printable(b"AB\x00C\xff"), "AB.C.");
    }
}
