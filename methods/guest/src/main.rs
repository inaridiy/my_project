use core::Outputs;
use json::parse;
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};

fn main() {
    let data: String = env::read();
    let sha = *Impl::hash_bytes(&data.as_bytes());
    let data = parse(&data).unwrap();
    let proven_val = data["critical_data"].as_u32().unwrap();
    let out = Outputs {
        data: proven_val,
        hash: sha,
    };
    env::commit(&out);
}
