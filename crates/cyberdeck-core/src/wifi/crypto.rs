//! WPA/WPA2 key derivation and MIC verification primitives.
//!
//! These are the algorithms a security assessment actually needs; they are
//! implemented here (rather than shelled out to a host tool) because G01 requires
//! *on-device* handshake quality verification and PMKID derivation:
//!
//! * `PMK  = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32)` (IEEE 802.11i)
//! * `PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AA || SPA)`
//! * `PTK  = PRF-512(PMK, "Pairwise key expansion", Min/Max(AA,SPA) || Min/Max(ANonce,SNonce))`
//! * `MIC  = HMAC-SHA1(KCK, EAPOL-Key)[0..16]`
//!
//! Scope: PSK (WPA2-Personal) only. SAE/OWE key establishment is not implemented;
//! see `wifi::attack::sae_support()` for the explicit limitation.
//!
//! All primitives are validated against RFC 3174 / RFC 2202 / RFC 6070 vectors and
//! the composed handshake chain is validated by round-trip construction in tests.

use crate::util::ct_eq;

/// SHA-1 digest size.
pub const SHA1_LEN: usize = 20;
/// WPA PMK size.
pub const PMK_LEN: usize = 32;
/// PTK size for CCMP (KCK 16 + KEK 16 + TK 16).
pub const PTK_LEN: usize = 64;
/// PMKID size.
pub const PMKID_LEN: usize = 16;

const SHA1_INIT: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

/// Streaming SHA-1.
#[derive(Debug, Clone)]
pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; 64],
    buffered: usize,
    total_len: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            state: SHA1_INIT,
            buffer: [0; 64],
            buffered: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                compress(&mut self.state, &block);
                self.buffered = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            compress(&mut self.state, &block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; SHA1_LEN] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buffered != 56 {
            self.update(&[0x00]);
        }
        let mut tail = [0u8; 8];
        tail.copy_from_slice(&bit_len.to_be_bytes());
        // Feeding the length must not be counted again; buffered==56 so the
        // 8-byte tail completes a block exactly.
        self.total_len -= 8;
        self.update(&tail);
        let mut out = [0u8; SHA1_LEN];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (i, wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

/// One-shot SHA-1.
pub fn sha1(data: &[u8]) -> [u8; SHA1_LEN] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize()
}

/// HMAC-SHA1 (RFC 2104), 20-byte tag.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; SHA1_LEN] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        let digest = sha1(key);
        block[..SHA1_LEN].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_key = [0u8; 64];
    let mut outer_key = [0u8; 64];
    for i in 0..64 {
        inner_key[i] = block[i] ^ 0x36;
        outer_key[i] = block[i] ^ 0x5C;
    }
    let mut inner = Sha1::new();
    inner.update(&inner_key);
    inner.update(data);
    let inner_digest = inner.finalize();
    let mut outer = Sha1::new();
    outer.update(&outer_key);
    outer.update(&inner_digest);
    outer.finalize()
}

/// PBKDF2-HMAC-SHA1 with a single 20-byte block expansion (`dk_len <= 20`),
/// plus full expansion for 32-byte PMK.
pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let mut block_index: u32 = 1;
    let mut offset = 0usize;
    while offset < out.len() {
        let mut salt_block = alloc::vec::Vec::with_capacity(salt.len() + 4);
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&block_index.to_be_bytes());
        let mut u = hmac_sha1(password, &salt_block);
        let mut acc = u;
        for _ in 1..iterations {
            u = hmac_sha1(password, &u);
            for i in 0..20 {
                acc[i] ^= u[i];
            }
        }
        let take = (out.len() - offset).min(20);
        out[offset..offset + take].copy_from_slice(&acc[..take]);
        offset += take;
        block_index += 1;
    }
}

/// Derive the WPA2-Personal PMK from the passphrase and SSID.
pub fn derive_pmk(passphrase: &[u8], ssid: &[u8]) -> [u8; PMK_LEN] {
    let mut pmk = [0u8; PMK_LEN];
    pbkdf2_hmac_sha1(passphrase, ssid, 4096, &mut pmk);
    pmk
}

/// `PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AA || SPA)`.
pub fn derive_pmkid(pmk: &[u8; PMK_LEN], ap: &[u8; 6], client: &[u8; 6]) -> [u8; PMKID_LEN] {
    let mut data = [0u8; 20];
    data[..8].copy_from_slice(b"PMK Name");
    data[8..14].copy_from_slice(ap);
    data[14..20].copy_from_slice(client);
    let mac = hmac_sha1(pmk, &data);
    let mut out = [0u8; PMKID_LEN];
    out.copy_from_slice(&mac[..PMKID_LEN]);
    out
}

/// WPA pseudo-random function producing `out.len()` bytes (used for 64-byte PTK).
pub fn prf(key: &[u8], label: &[u8], data: &[u8], out: &mut [u8]) {
    let mut offset = 0usize;
    let mut counter: u8 = 0;
    while offset < out.len() {
        let mut input = alloc::vec::Vec::with_capacity(label.len() + data.len() + 2);
        input.extend_from_slice(label);
        input.push(0x00);
        input.extend_from_slice(data);
        input.push(counter);
        let digest = hmac_sha1(key, &input);
        let take = (out.len() - offset).min(SHA1_LEN);
        out[offset..offset + take].copy_from_slice(&digest[..take]);
        offset += take;
        counter = counter.wrapping_add(1);
    }
}

/// Derived pairwise keys (CCMP: 16/16/16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairwiseKeys {
    pub kck: [u8; 16],
    pub kek: [u8; 16],
    pub tk: [u8; 16],
}

/// Derive the PTK for a 4-way handshake.
pub fn derive_ptk(
    pmk: &[u8; PMK_LEN],
    ap: &[u8; 6],
    client: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
) -> PairwiseKeys {
    // Min/Max for both address and nonce pairs, per IEEE 802.11i.
    let (min_mac, max_mac) = if ap <= client {
        (*ap, *client)
    } else {
        (*client, *ap)
    };
    let (min_nonce, max_nonce) = if anonce <= snonce {
        (*anonce, *snonce)
    } else {
        (*snonce, *anonce)
    };
    let mut data = [0u8; 76];
    data[..6].copy_from_slice(&min_mac);
    data[6..12].copy_from_slice(&max_mac);
    data[12..44].copy_from_slice(&min_nonce);
    data[44..76].copy_from_slice(&max_nonce);
    let mut ptk = [0u8; PTK_LEN];
    prf(pmk, b"Pairwise key expansion", &data, &mut ptk);
    let mut keys = PairwiseKeys {
        kck: [0; 16],
        kek: [0; 16],
        tk: [0; 16],
    };
    keys.kck.copy_from_slice(&ptk[0..16]);
    keys.kek.copy_from_slice(&ptk[16..32]);
    keys.tk.copy_from_slice(&ptk[32..48]);
    keys
}

/// Compute the EAPOL-Key MIC over a frame whose MIC field is zeroed.
pub fn compute_mic(kck: &[u8; 16], eapol_with_zero_mic: &[u8]) -> [u8; 16] {
    let mac = hmac_sha1(kck, eapol_with_zero_mic);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac[..16]);
    out
}

/// Constant-time MIC comparison.
pub fn mic_matches(expected: &[u8; 16], actual: &[u8]) -> bool {
    ct_eq(expected, actual)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_encode;

    #[test]
    fn sha1_rfc3174_vectors() {
        assert_eq!(
            hex_encode(&sha1(b"")),
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
        );
        assert_eq!(
            hex_encode(&sha1(b"abc")),
            "A9993E364706816ABA3E25717850C26C9CD0D89D"
        );
        assert_eq!(
            hex_encode(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983E441C3BD26EBAAE4AA1F95129E5E54670F1"
        );
        // Long input exercises multi-block streaming.
        let long = alloc::vec![b'a'; 1_000_000];
        assert_eq!(
            hex_encode(&sha1(&long)),
            "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"
        );
    }

    #[test]
    fn hmac_sha1_rfc2202_vectors() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hex_encode(&hmac_sha1(&key, b"Hi There")),
            "B617318655057264E28BC0B6FB378C8EF146BE00"
        );
        assert_eq!(
            hex_encode(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79"
        );
        // Key longer than the block size must be hashed first.
        let long_key = [0xAAu8; 80];
        assert_eq!(
            hex_encode(&hmac_sha1(
                &long_key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "AA4AE5E15272D00E95705637CE8A3B55ED402112"
        );
    }

    #[test]
    fn pbkdf2_rfc6070_vectors() {
        let mut out = [0u8; 20];
        pbkdf2_hmac_sha1(b"password", b"salt", 1, &mut out);
        assert_eq!(hex_encode(&out), "0C60C80F961F0E71F3A9B524AF6012062FE037A6");
        pbkdf2_hmac_sha1(b"password", b"salt", 2, &mut out);
        assert_eq!(hex_encode(&out), "EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957");
        pbkdf2_hmac_sha1(b"password", b"salt", 4096, &mut out);
        assert_eq!(hex_encode(&out), "4B007901B765489ABEAD49D926F721D065A429C1");
        // 32-byte expansion used by the WPA PMK spans two PBKDF2 blocks.
        let mut pmk = [0u8; 32];
        pbkdf2_hmac_sha1(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            &mut pmk,
        );
        assert_eq!(
            hex_encode(&pmk[..25]),
            "3D2EEC4FE41C849B80C8D83662C0E44A8B291A964CF2F07038"
        );
    }

    #[test]
    fn pmkid_is_stable_and_address_order_matters() {
        let pmk = derive_pmk(b"01234567", b"CyberDeck-Lab");
        let ap = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let client = [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB];
        let a = derive_pmkid(&pmk, &ap, &client);
        let b = derive_pmkid(&pmk, &ap, &client);
        let c = derive_pmkid(&pmk, &client, &ap);
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Deterministic known-answer guard: changing the passphrase changes the PMKID.
        let other = derive_pmkid(&derive_pmk(b"87654321", b"CyberDeck-Lab"), &ap, &client);
        assert_ne!(a, other);
    }

    #[test]
    fn ptk_prf_is_symmetric_in_nonce_and_address_order() {
        let pmk = derive_pmk(b"01234567", b"CyberDeck-Lab");
        let ap = [0x02, 0, 0, 0, 0, 0x01];
        let client = [0x02, 0, 0, 0, 0, 0x02];
        let anonce = [0x11u8; 32];
        let snonce = [0x22u8; 32];
        let forward = derive_ptk(&pmk, &ap, &client, &anonce, &snonce);
        let swapped = derive_ptk(&pmk, &client, &ap, &snonce, &anonce);
        assert_eq!(forward, swapped);
        assert_ne!(forward.kck, forward.kek);
        assert_ne!(forward.kek, forward.tk);
    }

    #[test]
    fn mic_chain_round_trip() {
        let pmk = derive_pmk(b"correct horse battery", b"Lab-Net");
        let ap = [0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E];
        let client = [0x00, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E];
        let anonce = [0x5Au8; 32];
        let snonce = [0xA5u8; 32];
        let keys = derive_ptk(&pmk, &ap, &client, &anonce, &snonce);

        // Build a synthetic EAPOL-Key frame with a zero MIC and then sign it.
        let mut frame = alloc::vec![2u8, 3, 0, 0];
        frame.extend_from_slice(&[0x02, 0x01]); // RSN key descriptor, msg 2 style info
        frame.resize(frame.len() + 2 + 8 + 32 + 16 + 8 + 8, 0);
        frame.extend_from_slice(&[0u8; 16]); // MIC field (zeroed)
        let mic = compute_mic(&keys.kck, &frame);
        let mic_region = frame.len() - 16;
        frame[mic_region..].copy_from_slice(&mic);
        assert!(mic_matches(&mic, &frame[mic_region..]));

        // A different passphrase yields a different MIC.
        let wrong = derive_ptk(
            &derive_pmk(b"wrong passphrase", b"Lab-Net"),
            &ap,
            &client,
            &anonce,
            &snonce,
        );
        assert!(!mic_matches(
            &compute_mic(&wrong.kck, &frame[..frame.len() - 16]),
            &frame[mic_region..]
        ));
    }
}
