use ring::{
    aead::{self, BoundKey, NonceSequence, AES_256_GCM, NONCE_LEN},
    digest::SHA256_OUTPUT_LEN,
    error,
    pbkdf2::{self, PBKDF2_HMAC_SHA256},
    rand::{SecureRandom, SystemRandom},
};
use std::num::NonZeroU32;

pub const SALT_LEN: usize = 16;

type AeadKey = [u8; SHA256_OUTPUT_LEN];
type AeadNonce = [u8; NONCE_LEN];
pub type Salt = [u8; SALT_LEN];

pub struct CounterNonceSequence {
    pub counter: u32,
}

impl CounterNonceSequence {
    pub fn new(n: &[u8]) -> CounterNonceSequence {
        let counter = ((n[0] as u32) << 24)
            + ((n[1] as u32) << 16)
            + ((n[2] as u32) << 8)
            + ((n[3] as u32) << 0);
        CounterNonceSequence { counter: counter }
    }
}

impl NonceSequence for CounterNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, error::Unspecified> {
        let mut nonce = AeadNonce::default();
        for i in 0..3 {
            nonce[(i * 4)..((i + 1) * 4)]
                .copy_from_slice(&(self.counter + (i as u32)).to_be_bytes());
        }

        self.counter += 3;
        aead::Nonce::try_assume_unique_for_key(&nonce)
    }
}

pub fn generate_salt() -> Result<Salt, error::Unspecified> {
    let sr = SystemRandom::new();
    let mut salt = Salt::default();
    sr.fill(&mut salt)?;
    Ok(salt)
}

pub fn derive_key(key: &[u8], salt: &Salt) -> AeadKey {
    let mut derived_key = AeadKey::default();
    pbkdf2::derive(
        PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100_000).unwrap(),
        salt,
        key,
        &mut derived_key,
    );
    derived_key
}

pub fn aead_encrypt(
    key: AeadKey,
    data: &mut Vec<u8>,
    nonce_sequence: CounterNonceSequence,
) -> Result<aead::Tag, error::Unspecified> {
    let unbound_key = aead::UnboundKey::new(&AES_256_GCM, &key).unwrap();
    let mut sealing_key = aead::SealingKey::new(unbound_key, nonce_sequence);

    sealing_key.seal_in_place_separate_tag(aead::Aad::empty(), data)
}

pub fn aead_decrypt<'data>(
    key: AeadKey,
    data: &'data mut Vec<u8>,
    nonce_sequence: CounterNonceSequence,
) -> Result<&mut [u8], error::Unspecified> {
    let unbound_key = aead::UnboundKey::new(&AES_256_GCM, &key).unwrap();
    let mut opening_key = aead::OpeningKey::new(unbound_key, nonce_sequence);

    opening_key.open_in_place(aead::Aad::empty(), data)
}
