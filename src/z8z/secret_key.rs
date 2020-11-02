use crate::z8z;
use concrete_lib::crypto_api;

#[derive(Debug, PartialEq)]
pub struct SecretKey {
    pub secret_key: crypto_api::LWESecretKey,
}

impl SecretKey {
    pub fn encrypt(&self, message: usize) -> z8z::Ciphertext {
        let m = message % z8z::MOD;
        let encoder: crypto_api::Encoder = crypto_api::Encoder::new_rounding_context(
            0.,
            z8z::MAX,
            z8z::NBBITPRECISION,
            z8z::NBBITPADDING,
        )
        .unwrap();

        let ct: crypto_api::LWE =
            crypto_api::LWE::encode_encrypt(&self.secret_key, m as f64, &encoder).unwrap();
        z8z::ciphertext::Ciphertext { ciphertext: ct }
    }

    pub fn decrypt(&self, ct: &z8z::Ciphertext) -> usize {
        let dec: f64 = ct.ciphertext.decrypt_decode(&self.secret_key).unwrap();
        z8z::round_modulo(dec) as usize
    }
}
