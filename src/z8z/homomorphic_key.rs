use crate::z8z;
use concrete_lib::crypto_api;
use concrete_lib::traits::{HomomorphicAdd, HomomorphicMul, HomomorphicSub};

#[derive(Debug, PartialEq, Clone)]
pub struct HomomorphicKey {
    pub bootstrapping_key: crypto_api::LWEBSK,
}

/// max function implementation
impl HomomorphicKey {
    #[allow(dead_code)]
    pub fn max(&self, left: &z8z::Ciphertext, right: &z8z::Ciphertext) -> z8z::Ciphertext {
        // subtraction
        let sub = left
            .ciphertext
            .sub_with_padding_exact(&right.ciphertext)
            .unwrap();

        // relu
        let rel = sub
            .bootstrap_with_function(
                &self.bootstrapping_key,
                |x| z8z::relu(x),
                &left.ciphertext.encoder,
            )
            .unwrap();

        // addition
        let add = rel.add_with_padding_exact(&right.ciphertext).unwrap();

        // modulo
        let res = add
            .bootstrap_with_function(
                &self.bootstrapping_key,
                |x| z8z::round_modulo(x),
                &left.ciphertext.encoder,
            )
            .unwrap();
        z8z::Ciphertext { ciphertext: res }
    }
}

/// homomorphic add implementation
impl HomomorphicAdd<&z8z::Ciphertext, z8z::Ciphertext> for HomomorphicKey {
    fn add(&self, left: &z8z::Ciphertext, right: &z8z::Ciphertext) -> z8z::Ciphertext {
        // addition
        let sum = left
            .ciphertext
            .add_with_padding_exact(&right.ciphertext)
            .unwrap();

        // modulo
        let res = sum
            .bootstrap_with_function(
                &self.bootstrapping_key,
                |x| z8z::round_modulo(x),
                &left.ciphertext.encoder,
            )
            .unwrap();

        z8z::Ciphertext { ciphertext: res }
    }

    fn add_inplace(&self, left: &mut z8z::Ciphertext, right: &z8z::Ciphertext) {
        let res = self.add(left, right);
        left.ciphertext = res.ciphertext;
    }
}

// cst add implementation
impl HomomorphicAdd<usize, z8z::Ciphertext> for HomomorphicKey {
    fn add(&self, left: &z8z::Ciphertext, right: usize) -> z8z::Ciphertext {
        let ct: crypto_api::LWE = left
            .ciphertext
            .add_constant_dynamic_encoder(right as f64)
            .unwrap();
        z8z::Ciphertext { ciphertext: ct }
    }

    fn add_inplace(&self, left: &mut z8z::Ciphertext, right: usize) {
        left.ciphertext
            .add_constant_dynamic_encoder_inplace(right as f64)
            .unwrap();
    }
}

// homomorphic sub implementation
impl HomomorphicSub<&z8z::Ciphertext, z8z::Ciphertext> for HomomorphicKey {
    fn sub(&self, left: &z8z::Ciphertext, right: &z8z::Ciphertext) -> z8z::Ciphertext {
        // subtraction
        let sub = left
            .ciphertext
            .sub_with_padding_exact(&right.ciphertext)
            .unwrap();

        // modulo
        let res = sub
            .bootstrap_with_function(
                &self.bootstrapping_key,
                |x| z8z::round_modulo(x),
                &left.ciphertext.encoder,
            )
            .unwrap();

        z8z::Ciphertext { ciphertext: res }
    }

    fn sub_inplace(&self, left: &mut z8z::Ciphertext, right: &z8z::Ciphertext) {
        let res = self.sub(left, right);
        left.ciphertext = res.ciphertext;
    }
}

// cst sub implementation
impl HomomorphicSub<usize, z8z::Ciphertext> for HomomorphicKey {
    fn sub(&self, left: &z8z::Ciphertext, right: usize) -> z8z::Ciphertext {
        let ct: crypto_api::LWE = left
            .ciphertext
            .add_constant_dynamic_encoder(-(right as f64))
            .unwrap();
        z8z::Ciphertext { ciphertext: ct }
    }

    fn sub_inplace(&self, left: &mut z8z::Ciphertext, right: usize) {
        left.ciphertext
            .add_constant_dynamic_encoder_inplace(-(right as f64))
            .unwrap();
    }
}

// homomorphic mul implementation
impl HomomorphicMul<&z8z::Ciphertext, z8z::Ciphertext> for HomomorphicKey {
    fn mul(&self, left: &z8z::Ciphertext, right: &z8z::Ciphertext) -> z8z::Ciphertext {
        // addition
        let posi = left
            .ciphertext
            .add_with_padding_exact(&right.ciphertext)
            .unwrap();

        // subtraction
        let nega = left
            .ciphertext
            .sub_with_padding_exact(&right.ciphertext)
            .unwrap();

        // modulo
        let mut res_posi = posi
            .bootstrap_with_function(
                &self.bootstrapping_key,
                |x| z8z::floor_modulo(x * x / 4.),
                &left.ciphertext.encoder,
            )
            .unwrap();

        // modulo
        let res_nega = nega
            .bootstrap_with_function(
                &self.bootstrapping_key,
                |x| z8z::floor_modulo(x * x / 4.),
                &left.ciphertext.encoder,
            )
            .unwrap();

        // subtraction
        res_posi.sub_with_padding_exact_inplace(&res_nega).unwrap();

        // modulo
        let res = res_posi
            .bootstrap_with_function(
                &self.bootstrapping_key,
                |x| z8z::round_modulo(x),
                &left.ciphertext.encoder,
            )
            .unwrap();

        z8z::Ciphertext { ciphertext: res }
    }

    fn mul_inplace(&self, left: &mut z8z::Ciphertext, right: &z8z::Ciphertext) {
        let res = self.mul(left, right);
        left.ciphertext = res.ciphertext;
    }
}

// cst mul implementation
impl HomomorphicMul<usize, z8z::Ciphertext> for HomomorphicKey {
    fn mul(&self, left: &z8z::Ciphertext, right: usize) -> z8z::Ciphertext {
        // multiplication and modulo
        let res = left
            .ciphertext
            .bootstrap_with_function(
                &self.bootstrapping_key,
                |x| z8z::round_modulo(x * (right as f64)),
                &left.ciphertext.encoder,
            )
            .unwrap();

        z8z::Ciphertext { ciphertext: res }
    }

    fn mul_inplace(&self, left: &mut z8z::Ciphertext, right: usize) {
        let res = self.mul(left, right);
        left.ciphertext = res.ciphertext;
    }
}

impl HomomorphicKey {
    #[allow(dead_code)]
    pub fn f<F: Fn(f64) -> f64>(&self, ct: &z8z::Ciphertext, f: F) -> z8z::Ciphertext {
        // function and modulo
        let res = ct
            .ciphertext
            .bootstrap_with_function(
                &self.bootstrapping_key,
                |x| z8z::round_modulo(f(z8z::round_modulo(x))),
                &ct.ciphertext.encoder,
            )
            .unwrap();

        z8z::Ciphertext { ciphertext: res }
    }

    #[allow(dead_code)]
    pub fn f_inplace<F: Fn(f64) -> f64>(&self, ct: &mut z8z::Ciphertext, f: F) {
        let res = self.f(ct, f);
        ct.ciphertext = res.ciphertext;
    }
}
