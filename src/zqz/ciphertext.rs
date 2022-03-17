//! A module containing a ciphertext structure.
use crate::zqz;
use crate::PARAMS;
use concrete::lwe::LWE;
use concrete::encoder::Encoder;
use concrete::lwe_bsk::LWEBSK;
use concrete::lwe_ksk::LWEKSK;
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use std::rc::Rc;
use zqz::keys::HomomorphicKey;
use zqz::max::Max;

/// An encrypted message.
#[derive(Debug, Clone, PartialEq)]
pub struct Ciphertext {
    pub(super) ciphertext: LWE,
    pub(super) evaluation_key: Rc<HomomorphicKey>,
}

fn bs_ks<F: Fn(f64) -> f64>(
    ciphertext: &LWE,
    bootstrapping_key: &LWEBSK,
    func: F,
    encoder: &Encoder,
    keyswitching_key: &LWEKSK,
) -> LWE {
    let res = ciphertext
        .bootstrap_with_function(bootstrapping_key, func, encoder)
        .unwrap();

    if PARAMS.with_ks {
        let res_ks = res.keyswitch(keyswitching_key).unwrap();
        return res_ks;
    } else {
        return res;
    }
}

impl Ciphertext {
    #[allow(dead_code)]
    pub fn eval<F: Fn(f64) -> f64>(&self, f: F) -> Ciphertext {
        // function and modulo
        let res = bs_ks(
            &self.ciphertext,
            &self.evaluation_key.bootstrapping,
            |x| zqz::utils::round_modulo(f(zqz::utils::round_modulo(x))),
            &self.ciphertext.encoder,
            &self.evaluation_key.keyswitching,
        );

        Ciphertext {
            ciphertext: res,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Adds two ciphertexts using the `+` operator.
impl Add<&Ciphertext> for &Ciphertext {
    type Output = Ciphertext;

    fn add(self, other: &Ciphertext) -> Self::Output {
        // addition
        let sum = self
            .ciphertext
            .add_with_padding_exact(&other.ciphertext)
            .unwrap();

        // modulo
        let res = bs_ks(
            &sum,
            &self.evaluation_key.bootstrapping,
            |x| zqz::utils::round_modulo(x),
            &self.ciphertext.encoder,
            &self.evaluation_key.keyswitching,
        );

        Ciphertext {
            ciphertext: res,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Adds an integer to a ciphertext using the `+` operator.
impl Add<usize> for &Ciphertext {
    type Output = Ciphertext;

    fn add(self, other: usize) -> Self::Output {
        let res: LWE = self
            .ciphertext
            .add_constant_dynamic_encoder(other as f64)
            .unwrap();

        Ciphertext {
            ciphertext: res,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Adds two ciphertexts using the `+=` operator.
impl AddAssign<&Ciphertext> for Ciphertext {
    fn add_assign(&mut self, other: &Ciphertext) {
        let res = &*self + other;
        self.ciphertext = res.ciphertext;
    }
}

// Adds an integer to a ciphertext using the `+=` operator.
impl AddAssign<usize> for Ciphertext {
    fn add_assign(&mut self, other: usize) {
        let res = &*self + other;
        self.ciphertext = res.ciphertext;
    }
}

// Substracts two ciphertexts using the `-` operator.
impl Sub<&Ciphertext> for &Ciphertext {
    type Output = Ciphertext;

    fn sub(self, other: &Ciphertext) -> Self::Output {
        // subtraction
        let sub = self
            .ciphertext
            .sub_with_padding_exact(&other.ciphertext)
            .unwrap();

        // modulo
        let res = bs_ks(
            &sub,
            &self.evaluation_key.bootstrapping,
            |x| zqz::utils::round_modulo(x),
            &self.ciphertext.encoder,
            &self.evaluation_key.keyswitching,
        );

        Ciphertext {
            ciphertext: res,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Substracts an integer to a ciphertext using the `-` operator.
impl Sub<usize> for &Ciphertext {
    type Output = Ciphertext;

    fn sub(self, other: usize) -> Self::Output {
        let res: LWE = self
            .ciphertext
            .add_constant_dynamic_encoder(-(other as f64))
            .unwrap();

        Ciphertext {
            ciphertext: res,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Substracts two ciphertexts using the `-=` operator.
impl SubAssign<&Ciphertext> for Ciphertext {
    fn sub_assign(&mut self, other: &Ciphertext) {
        let res = &*self - other;
        self.ciphertext = res.ciphertext;
    }
}

// Substracts an integer to a ciphertext using the `-=` operator.
impl SubAssign<usize> for Ciphertext {
    fn sub_assign(&mut self, other: usize) {
        let res = &*self - other;
        self.ciphertext = res.ciphertext;
    }
}

// Multiplies two ciphertexts using the `*` operator.
impl Mul<&Ciphertext> for &Ciphertext {
    type Output = Ciphertext;

    fn mul(self, other: &Ciphertext) -> Self::Output {
        // addition
        let posi = self
            .ciphertext
            .add_with_padding_exact(&other.ciphertext)
            .unwrap();

        // subtraction
        let nega = self
            .ciphertext
            .sub_with_padding_exact(&other.ciphertext)
            .unwrap();

        // modulo
        let mut res_posi = bs_ks(
            &posi,
            &self.evaluation_key.bootstrapping,
            |x| zqz::utils::floor_modulo(x * x / 4.),
            &self.ciphertext.encoder,
            &self.evaluation_key.keyswitching,
        );

        // modulo
        let res_nega = bs_ks(
            &nega,
            &self.evaluation_key.bootstrapping,
            |x| zqz::utils::floor_modulo(x * x / 4.),
            &self.ciphertext.encoder,
            &self.evaluation_key.keyswitching,
        );

        // subtraction
        res_posi.sub_with_padding_exact_inplace(&res_nega).unwrap();

        // modulo
        let res = bs_ks(
            &res_posi,
            &self.evaluation_key.bootstrapping,
            |x| zqz::utils::round_modulo(x),
            &self.ciphertext.encoder,
            &self.evaluation_key.keyswitching,
        );

        Ciphertext {
            ciphertext: res,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Multiplies an integer with a ciphertext using the `*` operator.
impl Mul<usize> for &Ciphertext {
    type Output = Ciphertext;

    fn mul(self, other: usize) -> Self::Output {
        let res = bs_ks(
            &self.ciphertext,
            &self.evaluation_key.bootstrapping,
            |x| zqz::utils::round_modulo(x * (other as f64)),
            &self.ciphertext.encoder,
            &self.evaluation_key.keyswitching,
        );

        Ciphertext {
            ciphertext: res,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Multiplies two ciphertexts using the `*=` operator.
impl MulAssign<&Ciphertext> for Ciphertext {
    fn mul_assign(&mut self, other: &Ciphertext) {
        let res = &*self * other;
        self.ciphertext = res.ciphertext;
    }
}

// Multiplies an integer with a ciphertext using the `*=` operator.
impl MulAssign<usize> for Ciphertext {
    fn mul_assign(&mut self, other: usize) {
        let res = &*self * other;
        self.ciphertext = res.ciphertext;
    }
}

// Compute the max between an integer and a ciphertext
impl Max<usize> for &Ciphertext {
    type Output = Ciphertext;
    fn max(self, rhs: usize) -> Self::Output {
        let res = bs_ks(
            &self.ciphertext,
            &self.evaluation_key.bootstrapping,
            |x| f64::max(x, (rhs % PARAMS.modulo) as f64),
            &self.ciphertext.encoder,
            &self.evaluation_key.keyswitching,
        );

        Ciphertext {
            ciphertext: res,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}

// Compute the max between a ciphertext and an integer
impl Max<&Ciphertext> for usize {
    type Output = Ciphertext;
    fn max(self, rhs: &Ciphertext) -> Self::Output {
        rhs.max(self)
    }
}

// Compute the max between two ciphertexts
impl Max<&Ciphertext> for &Ciphertext {
    type Output = Ciphertext;
    fn max(self, rhs: &Ciphertext) -> Self::Output {
        // subtraction
        let sub = self
            .ciphertext
            .sub_with_padding_exact(&rhs.ciphertext)
            .unwrap();

        // relu
        let rel = bs_ks(
            &sub,
            &self.evaluation_key.bootstrapping,
            |x| zqz::utils::relu(x),
            &self.ciphertext.encoder,
            &self.evaluation_key.keyswitching,
        );

        // addition
        let add = rel.add_with_padding_exact(&rhs.ciphertext).unwrap();

        // modulo
        let res = bs_ks(
            &add,
            &self.evaluation_key.bootstrapping,
            |x| zqz::utils::round_modulo(x),
            &self.ciphertext.encoder,
            &self.evaluation_key.keyswitching,
        );

        Ciphertext {
            ciphertext: res,
            evaluation_key: self.evaluation_key.clone(),
        }
    }
}
