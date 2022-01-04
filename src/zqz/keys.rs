//! A module containing the different kind of keys used in the program.
use crate::zqz;
use crate::PARAMS;
use concrete;
use std::rc::Rc;

const SECRET_FILE: &str = "secret_key.json";
const BOOTSTRAPPING_FILE: &str = "bootstrapping_key.txt";
const KEYSWITCHING_FILE: &str = "keyswitching_key.txt";

/// A set of keys publicly available, allowing to perform bootstrap and keyswitch operations on
/// ciphertext.
#[derive(Debug, PartialEq)]
pub struct HomomorphicKey {
    pub(super) bootstrapping: concrete::LWEBSK,
    pub(super) keyswitching: concrete::LWEKSK,
}

/// A secret key available only to the user side, allowing to encrypt ant decrypt data.
#[derive(Debug, PartialEq)]
pub struct EncryptKey {
    pub(super) secret:concrete::LWESecretKey,
    pub(super) evaluation: Rc<HomomorphicKey>,
}

impl EncryptKey {
    /// Generates a new encrypt key
    pub fn new() -> EncryptKey {
        // We generate the lwe secret key
        let rlwe_sk:concrete::RLWESecretKey =
        concrete::RLWESecretKey::new(&PARAMS.rlwe_setting);
        let lwe_sk:concrete::LWESecretKey = if PARAMS.with_ks {
            concrete::LWESecretKey::new(&PARAMS.lwe_setting)
        } else {
            rlwe_sk.to_lwe_secret_key()
        };
        // We generats the bootstrapping and keyswitching keys
        let bsk:  concrete::LWEBSK =
        concrete::LWEBSK::new(&lwe_sk, &rlwe_sk, PARAMS.bs_base_log, PARAMS.bs_level);
        let ksk:  concrete::LWEKSK = if PARAMS.with_ks {
            concrete::LWEKSK::new(
                &rlwe_sk.to_lwe_secret_key(),
                &lwe_sk,
                PARAMS.ks_base_log,
                PARAMS.ks_level,
            )
        } else {
            concrete::LWEKSK::zero(
                &rlwe_sk.to_lwe_secret_key(),
                &lwe_sk,
                PARAMS.ks_base_log,
                PARAMS.ks_level,
            )
        };
        // We pack the homomorphic keys
        let hk = HomomorphicKey {
            bootstrapping: bsk,
            keyswitching: ksk,
        };

        EncryptKey {
            secret: lwe_sk,
            evaluation: Rc::new(hk),
        }
    }

    /// Generates a new encrypt key
    #[allow(dead_code)]
    pub fn new_zero() -> EncryptKey {
        // We generate the lwe secret key
        let rlwe_sk:  concrete::RLWESecretKey =
        concrete::RLWESecretKey::new(&PARAMS.rlwe_setting);
        let lwe_sk:  concrete::LWESecretKey = rlwe_sk.to_lwe_secret_key();
        // We generats the bootstrapping and keyswitching keys
        let bsk:  concrete::LWEBSK =
        concrete::LWEBSK::zero(&lwe_sk, &rlwe_sk, PARAMS.bs_base_log, PARAMS.bs_level);
        let ksk:  concrete::LWEKSK =
        concrete::LWEKSK::zero(&lwe_sk, &lwe_sk, PARAMS.ks_base_log, PARAMS.ks_level);
        // We pack the homomorphic keys
        let hk = HomomorphicKey {
            bootstrapping: bsk,
            keyswitching: ksk,
        };

        EncryptKey {
            secret: lwe_sk,
            evaluation: Rc::new(hk),
        }
    }

    /// Checks whether the keys with this prefix exist or not.
    pub fn keys_exist(prefix: &str) -> bool {
        use std::path::Path;
        Path::new(format!("{}_{}", prefix, SECRET_FILE).as_str()).exists()
            && Path::new(format!("{}_{}", prefix, BOOTSTRAPPING_FILE).as_str()).exists()
            && Path::new(format!("{}_{}", prefix, KEYSWITCHING_FILE).as_str()).exists()
    }

    /// Saves the encryption keys to files
    pub fn save_to_files(&self, prefix: &str) {
        self.secret
            .save(format!("{}_{}", prefix, SECRET_FILE).as_str())
            .unwrap();
        self.evaluation
            .bootstrapping
            .save(format!("{}_{}", prefix, BOOTSTRAPPING_FILE).as_str());
        self.evaluation
            .keyswitching
            .save(format!("{}_{}", prefix, KEYSWITCHING_FILE).as_str());
    }

    /// Loads the encryption keys from files
    pub fn load_from_files(prefix: &str) -> EncryptKey {
        let secret_key =
        concrete::LWESecretKey::load(format!("{}_{}", prefix, SECRET_FILE).as_str())
                .expect("No Secret Key File");
        let bsk =  concrete::LWEBSK::load(format!("{}_{}", prefix, BOOTSTRAPPING_FILE).as_str());
        let ksk =  concrete::LWEKSK::load(format!("{}_{}", prefix, KEYSWITCHING_FILE).as_str());
        let hk = HomomorphicKey {
            bootstrapping: bsk,
            keyswitching: ksk,
        };
        EncryptKey {
            secret: secret_key,
            evaluation: Rc::new(hk),
        }
    }

    /// Encrypt the given message
    pub fn encrypt(&self, message: usize) -> zqz::ciphertext::Ciphertext {
        let m = message % PARAMS.modulo;
        let encoder:  concrete::Encoder =  concrete::Encoder::new_rounding_context(
            0.,
            PARAMS.max,
            PARAMS.nb_bit_precision,
            PARAMS.nb_bit_padding,
        )
        .unwrap();

        let ct:  concrete::LWE =
        concrete::LWE::encode_encrypt(&self.secret, m as f64, &encoder).unwrap();
        zqz::ciphertext::Ciphertext {
            ciphertext: ct,
            evaluation_key: self.evaluation.clone(),
        }
    }

    /// We decrypt the ciphertext
    pub fn decrypt(&self, ct: &zqz::ciphertext::Ciphertext) -> usize {
        let dec: f64 = ct.ciphertext.decrypt_decode(&self.secret).unwrap();
        zqz::utils::round_modulo(dec) as usize
    }
}
