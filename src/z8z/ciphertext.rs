use concrete_lib::crypto_api;

#[derive(Debug, Clone, PartialEq)]
pub struct Ciphertext {
    pub ciphertext: crypto_api::LWE,
}
