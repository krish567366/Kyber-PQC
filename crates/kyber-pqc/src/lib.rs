//! Native ML-KEM-512 (Kyber-512) key encapsulation for Rust.

use thiserror::Error;

pub use kyber_pqc_sys::{
    CIPHERTEXT_BYTES, PRIVATE_KEY_BYTES, PUBLIC_KEY_BYTES, SHARED_SECRET_BYTES,
};

#[derive(Debug, Error)]
pub enum KyberError {
    #[error("key generation failed")]
    KeygenFailed,
    #[error("encapsulation failed")]
    EncapsulateFailed,
    #[error("decapsulation failed")]
    DecapsulateFailed,
    #[error("invalid public key length: expected {PUBLIC_KEY_BYTES}, got {0}")]
    InvalidPublicKey(usize),
    #[error("invalid private key length: expected {PRIVATE_KEY_BYTES}, got {0}")]
    InvalidPrivateKey(usize),
    #[error("invalid ciphertext length: expected {CIPHERTEXT_BYTES}, got {0}")]
    InvalidCiphertext(usize),
}

pub struct KeyPair {
    pub public_key: [u8; PUBLIC_KEY_BYTES],
    pub private_key: [u8; PRIVATE_KEY_BYTES],
}

pub struct Ciphertext {
    pub data: [u8; CIPHERTEXT_BYTES],
    pub shared_secret: [u8; SHARED_SECRET_BYTES],
}

pub fn generate_keypair() -> Result<KeyPair, KyberError> {
    let mut public_key = [0u8; PUBLIC_KEY_BYTES];
    let mut private_key = [0u8; PRIVATE_KEY_BYTES];

    let rc = unsafe {
        kyber_pqc_sys::kyber_pqc_keypair(public_key.as_mut_ptr(), private_key.as_mut_ptr())
    };
    if rc != 0 {
        return Err(KyberError::KeygenFailed);
    }

    Ok(KeyPair {
        public_key,
        private_key,
    })
}

pub fn encapsulate(public_key: &[u8; PUBLIC_KEY_BYTES]) -> Result<Ciphertext, KyberError> {
    let mut ciphertext = [0u8; CIPHERTEXT_BYTES];
    let mut shared_secret = [0u8; SHARED_SECRET_BYTES];

    let rc = unsafe {
        kyber_pqc_sys::kyber_pqc_encapsulate(
            public_key.as_ptr(),
            ciphertext.as_mut_ptr(),
            shared_secret.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(KyberError::EncapsulateFailed);
    }

    Ok(Ciphertext {
        data: ciphertext,
        shared_secret,
    })
}

pub fn decapsulate(
    ciphertext: &[u8; CIPHERTEXT_BYTES],
    private_key: &[u8; PRIVATE_KEY_BYTES],
) -> Result<[u8; SHARED_SECRET_BYTES], KyberError> {
    let mut shared_secret = [0u8; SHARED_SECRET_BYTES];

    let rc = unsafe {
        kyber_pqc_sys::kyber_pqc_decapsulate(
            private_key.as_ptr(),
            ciphertext.as_ptr(),
            shared_secret.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(KyberError::DecapsulateFailed);
    }

    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_exchange() {
        let kp = generate_keypair().expect("keygen");
        let ct = encapsulate(&kp.public_key).expect("encaps");
        let ss = decapsulate(&ct.data, &kp.private_key).expect("decaps");
        assert_eq!(ss, ct.shared_secret);
    }
}
