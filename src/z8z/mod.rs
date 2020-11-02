use concrete_lib::crypto_api;

pub mod ciphertext;
pub use ciphertext::*;
pub mod homomorphic_key;
pub use homomorphic_key::*;
pub mod secret_key;
pub use secret_key::*;
#[cfg(test)]
mod tests;

pub use concrete_lib::traits::{HomomorphicAdd, HomomorphicMul, HomomorphicSub};

pub const NBBITPRECISION: usize = 3;
pub const MOD: usize = 1 << NBBITPRECISION;
pub const MAX: f64 = (MOD - 1) as f64;
pub const NBBITPADDING: usize = 2;
pub const BASELOG: usize = 6; //8
pub const LEVEL: usize = 4; //5
pub const RLWESETTING: crypto_api::RLWEParams = crypto_api::RLWE128_1024_1;

#[allow(dead_code)]
pub fn setup() -> (secret_key::SecretKey, homomorphic_key::HomomorphicKey) {
    let rlwe_sk: crypto_api::RLWESecretKey = crypto_api::RLWESecretKey::new(&RLWESETTING);
    let lwe_sk: crypto_api::LWESecretKey = rlwe_sk.to_lwe_secret_key();
    let bsk: crypto_api::LWEBSK = crypto_api::LWEBSK::new(&lwe_sk, &rlwe_sk, BASELOG, LEVEL);
    (
        secret_key::SecretKey { secret_key: lwe_sk },
        homomorphic_key::HomomorphicKey {
            bootstrapping_key: bsk,
        },
    )
}

#[allow(dead_code)]
pub fn setup_zero() -> (secret_key::SecretKey, homomorphic_key::HomomorphicKey) {
    let rlwe_sk: crypto_api::RLWESecretKey = crypto_api::RLWESecretKey::new(&RLWESETTING);
    let lwe_sk: crypto_api::LWESecretKey = rlwe_sk.to_lwe_secret_key();
    let bsk: crypto_api::LWEBSK = crypto_api::LWEBSK::zero(&lwe_sk, &rlwe_sk, BASELOG, LEVEL);
    (
        secret_key::SecretKey { secret_key: lwe_sk },
        homomorphic_key::HomomorphicKey {
            bootstrapping_key: bsk,
        },
    )
}

#[allow(dead_code)]
pub fn setup_save() -> (secret_key::SecretKey, homomorphic_key::HomomorphicKey) {
    // setup
    let (sk, hek) = setup();

    // we write the keys in files
    sk.secret_key.save("zqz_lwe_key.json").unwrap();
    hek.bootstrapping_key
        .write_in_file_bytes("zqz_bsk_bytes.txt");

    (sk, hek)
}

#[allow(dead_code)]
pub fn setup_load() -> (secret_key::SecretKey, homomorphic_key::HomomorphicKey) {
    // load the keys
    let lwe_sk: crypto_api::LWESecretKey =
        crypto_api::LWESecretKey::load("zqz_lwe_key.json").unwrap();
    let bsk: crypto_api::LWEBSK = crypto_api::LWEBSK::read_in_file_bytes("zqz_bsk_bytes.txt");
    (
        secret_key::SecretKey { secret_key: lwe_sk },
        homomorphic_key::HomomorphicKey {
            bootstrapping_key: bsk,
        },
    )
}

/// compute the round and then the modulo
pub fn round_modulo(x: f64) -> f64 {
    let tmp = (x.round()) as i32;
    let i: i32 = tmp % (MOD as i32);
    let res = if i < 0 { i + (MOD as i32) } else { i };
    res as f64
}

/// compute the floor and then the modulo
pub fn floor_modulo(x: f64) -> f64 {
    let tmp = x % (MOD as f64);
    let res = if tmp < 0. { tmp + MOD as f64 } else { tmp };
    res.floor()
}

/// compute the relu
pub fn relu(x: f64) -> f64 {
    f64::max(0., x)
}
