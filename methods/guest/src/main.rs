use core::{encrypt_aes, Outputs};
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};

fn main() {
    let (plaintext, key): (String, [u8; 16]) = env::read();
    let sha = *Impl::hash_bytes(&plaintext.as_bytes());
    let encrypted = encrypt_aes(&plaintext, &key);
    let out = Outputs {
        encrypted,
        hash: sha,
    };
    env::commit(&out);
}
