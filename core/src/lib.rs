// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Outputs {
    pub encrypted: Vec<u8>,
    pub hash: Digest,
}

const BLOCK_SIZE: usize = 16;

pub fn encrypt_aes(plaintext: &str, key: &[u8; 16]) -> Vec<u8> {
    let mut padded = plaintext.as_bytes().to_vec();
    let padding = BLOCK_SIZE - (padded.len() % BLOCK_SIZE);
    padded.extend(vec![padding as u8; padding]);

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut ciphertext = Vec::new();

    for chunk in padded.chunks_exact(BLOCK_SIZE) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
    }

    ciphertext
}

pub fn decrypt_aes(key: &[u8; 16], ciphertext: Vec<u8>) -> String {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut plaintext = Vec::new();

    for chunk in ciphertext.chunks_exact(BLOCK_SIZE) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        plaintext.extend_from_slice(&block);
    }

    if let Some(&padding) = plaintext.last() {
        let len = plaintext.len();
        plaintext.truncate(len - padding as usize);
    }

    String::from_utf8(plaintext).expect("Invalid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let key = [0u8; 16]; // テスト用の32バイトキー

        let plaintext = "Hello, World!";

        // 暗号化
        let encrypted = encrypt_aes(plaintext, &key);

        // 復号化
        let decrypted = decrypt_aes(&key, encrypted);

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_padding() {
        let key = [0u8; 16];

        // ブロックサイズ(16バイト)より長いテキスト
        let plaintext = "This is a longer text that needs padding";

        let encrypted = encrypt_aes(plaintext, &key);
        let decrypted = decrypt_aes(&key, encrypted);

        assert_eq!(plaintext, decrypted);
    }
}
