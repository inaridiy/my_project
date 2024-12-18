use core::{encrypt_aes, Outputs};
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};

fn main() {
    let (plaintext, key, black_list): (String, [u8; 16], Vec<String>) = env::read();
    let sha = *Impl::hash_bytes(&plaintext.as_bytes());
    let encrypted = encrypt_aes(&plaintext, &key);

    let is_black_listed = black_list.iter().any(|word| plaintext.contains(word));

    let out = Outputs {
        encrypted,
        hash: sha,
        is_black_listed,
    };
    env::commit(&out);
}
