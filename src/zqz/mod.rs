// A module allowing to perform encrypted computations on Z/qZ.
use concrete;



pub mod ciphertext;
pub mod keys;
pub mod max;
pub mod utils;
#[cfg(test)]
mod tests;

// A structure representing the parameters of the
pub struct Parameters {
    pub nb_bit_precision: usize,
    pub modulo: usize,
    pub max: f64,
    pub nb_bit_padding: usize,
    pub bs_base_log: usize,
    pub bs_level: usize,
    pub ks_base_log: usize,
    pub ks_level: usize,
    pub rlwe_setting:  concrete::RLWEParams,
    pub lwe_setting:  concrete::LWEParams,
    pub with_ks: bool,
}

impl Parameters {
    // Generates a prefix used to save the keys to files, whose names have a common prefix.
    pub fn gen_prefix(&self) -> String {
        if self.with_ks {
            let res: String = format!(
                "lwe_{}_rlwe_{}_{}_bbs_{}_lbs_{}_bks_{}_lks_{}",
                self.lwe_setting.dimension,
                self.rlwe_setting.polynomial_size,
                self.rlwe_setting.dimension,
                self.bs_base_log,
                self.bs_level,
                self.ks_base_log,
                self.ks_level
            );

            res
        } else {
            let res: String = format!(
                "rlwe_{}_{}_bbs_{}_lbs_{}",
                self.rlwe_setting.polynomial_size,
                self.rlwe_setting.dimension,
                self.bs_base_log,
                self.bs_level
            );
            res
        }
    }
}

#[macro_export]
macro_rules! new_parameters {
    (
        $nb_bit_precision: expr,
        $nb_bit_padding: expr,
        $bs_base_log: expr,
        $bs_level: expr,
        $ks_base_log: expr,
        $ks_level: expr,
        $rlwe_setting:expr,
        $lwe_setting: expr,
        $with_ks: expr) => {
        crate::zqz::Parameters {
            nb_bit_precision: $nb_bit_precision,
            modulo: 1 << $nb_bit_precision,
            max: ((1 << $nb_bit_precision) - 1) as f64,
            nb_bit_padding: $nb_bit_padding,
            bs_base_log: $bs_base_log,
            bs_level: $bs_level,
            ks_base_log: $ks_base_log,
            ks_level: $ks_level,
            rlwe_setting: $rlwe_setting,
            lwe_setting: $lwe_setting,
            with_ks: $with_ks,
        }
    };
}
