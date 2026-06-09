#![allow(non_camel_case_types, unsafe_op_in_unsafe_fn)]

use std::os::raw::c_int;

pub const PUBLIC_KEY_BYTES: usize = 800;
pub const PRIVATE_KEY_BYTES: usize = 1632;
pub const CIPHERTEXT_BYTES: usize = 768;
pub const SHARED_SECRET_BYTES: usize = 32;

extern "C" {
    pub fn kyber_pqc_keypair(public_key: *mut u8, private_key: *mut u8) -> c_int;
    pub fn kyber_pqc_encapsulate(
        public_key: *const u8,
        ciphertext: *mut u8,
        shared_secret: *mut u8,
    ) -> c_int;
    pub fn kyber_pqc_decapsulate(
        private_key: *const u8,
        ciphertext: *const u8,
        shared_secret: *mut u8,
    ) -> c_int;
}
