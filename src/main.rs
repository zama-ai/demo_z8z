//! A module containing a generic demonstration of computations over encrypted Z/qZ numbers.
use colored::Colorize;
#[allow(unused)]
use concrete::crypto_api::{LWEParams, LWE128_1024, LWE128_750, RLWE128_1024_1, RLWE128_2048_1};
use std::convert::TryInto;

#[macro_use]
mod zqz;
use zqz::keys::EncryptKey;
use zqz::max::max;

// We determine the cryptographic parameters depending on the compilation flag used.
#[cfg(not(any(feature = "z8z-ks", feature = "z16z-ks")))]
const PARAMS: zqz::Parameters =
    new_parameters!(3, 2, 6, 4, 1, 1, RLWE128_1024_1, LWE128_1024, false);
#[cfg(feature = "z16z-ks")]
const PARAMS: zqz::Parameters = new_parameters!(4, 2, 7, 3, 2, 7, RLWE128_2048_1, LWE128_750, true);
#[cfg(feature = "z8z-ks")]
// We define the cryptographic parameters of the demo
const PARAMS: zqz::Parameters = new_parameters!(3, 2, 7, 3, 2, 7, RLWE128_1024_1, LWE128_750, true);

fn main() {
    let reader = std::io::stdin();
    let mut reader_buffer = String::new();

    // Generating / Loading keys
    measure_duration!("1. Key Loading...",[
        let sk = if !EncryptKey::keys_exist(&PARAMS.gen_prefix()) {
            let key = EncryptKey::new();
            key.save_to_files(&PARAMS.gen_prefix());
            key
        } else {
            EncryptKey::load_from_files(&PARAMS.gen_prefix())
        };
    ]);
    reader.read_line(&mut reader_buffer).unwrap();

    // Encryption
    measure_duration!("2. Encryption... ",[
        let ct1 = sk.encrypt(4);
        let ct2 = sk.encrypt(7);
        let ct3 = sk.encrypt(5);
    ]);

    // Homomorphic computation
    measure_duration!("3. Homomorphic computation... ", [
        let mut ct_res = &ct1 * &ct2; // res <- m1 * m2
        ct_res = &ct_res + &ct3; // res <- res + m3
        ct_res = &ct_res + 2; // res <- res + 2
        ct_res = &ct_res * 3; // res <- res * 3
    ]);

    // Decryption
    measure_duration!("4. Decryption... ", [
        let res = sk.decrypt(&ct_res);
    ]);

    // Circuit result
    let s_res = format!(
        "{} mod {}",
        res,
        2_usize.pow(PARAMS.nb_bit_precision.try_into().unwrap())
    );
    println!(
        "-> Output of the circuit (should be {}): {}",
        105 % PARAMS.modulo,
        s_res.blue().bold()
    );

    reader.read_line(&mut reader_buffer).unwrap();

    // Max computation
    measure_duration!("5. Max computation: max(4,7)... ", [
        let ct_max_ct = max(&ct1, &ct2); // res <- max(m1, m2)
    ]);

    // Decryption
    measure_duration!("6. Decryption", [
        let res_ct = sk.decrypt(&ct_max_ct);
    ]);

    // Max result
    let s_res = format!(
        "{} mod {}",
        res_ct,
        2_usize.pow(PARAMS.nb_bit_precision.try_into().unwrap())
    );
    println!("-> Output (should be 7): {}", s_res.blue().bold());

    reader.read_line(&mut reader_buffer).unwrap();

    // Function evaluation
    measure_duration!("7. Function evaluation f(x)=x^3 with x=5... ", [
        let ct_ev = ct3.eval(|x| f64::powi(x, 3));
    ]);

    // Decryption
    measure_duration!("8. Decryption...", [
        let res = sk.decrypt(&ct_ev);
    ]);

    // Max result
    let s_res = format!("{} mod {}", res, PARAMS.modulo);
    println!(
        "-> Output (should be {}): {}",
        5 * 5 * 5 % PARAMS.modulo,
        s_res.blue().bold()
    );
}
