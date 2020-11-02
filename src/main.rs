mod z8z;
use colored::Colorize;
use std::io;
use std::io::Write;
use std::time::SystemTime;
use z8z::*;

fn main() {
    // setup
    print!("1. Key loading... ");
    io::stdout().flush().unwrap();
    let now = SystemTime::now();
    let (sk, hek) = z8z::setup();
    // let (sk, hek) = z8z::setup_load();
    let time = now.elapsed().unwrap().as_millis() as f64 / 1000.;
    let s_time = format!("{} s", time);
    println!("{}", s_time.green().bold());
    let mut _input = String::new();

    // encryption
    print!("2. Encryption... ");
    let now = SystemTime::now();
    let ct1 = sk.encrypt(4);
    let ct2 = sk.encrypt(7);
    let ct3 = sk.encrypt(5);
    let time = now.elapsed().unwrap().as_millis() as f64 / 1000.;
    let s_time = format!("{} s", time);
    println!("{}", s_time.green().bold());

    // homomorphic computation
    print!("3. Homomorphic computation... ");
    let now = SystemTime::now();
    let mut ct_res = hek.mul(&ct1, &ct2); // res <- m1 * m2
    ct_res = hek.add(&ct_res, &ct3); // res <- res + m3
    ct_res = hek.add(&ct_res, 2); // res <- res + 2
    ct_res = hek.mul(&ct_res, 3); // res <- res * 3
    let time = now.elapsed().unwrap().as_millis() as f64 / 1000.;
    let s_time = format!("{} s", time);
    println!("{}", s_time.green().bold());

    // decryption
    print!("4. Decryption... ");
    let now = SystemTime::now();
    let res = sk.decrypt(&ct_res);
    let time = now.elapsed().unwrap().as_millis() as f64 / 1000.;
    let s_time = format!("{} s", time);
    println!("{}", s_time.green().bold());

    // circuit result
    let s_res = format!("{} mod 8", res);
    println!(
        "-> Output of the circuit (should be 1): {}",
        s_res.blue().bold()
    );

    // max computation
    print!("5. Max computation... ");
    let now = SystemTime::now();
    let ct_max = hek.max(&ct1, &ct2); // res <- max(m1, m2)
    let time = now.elapsed().unwrap().as_millis() as f64 / 1000.;
    let s_time = format!("{} s", time);
    println!("{}", s_time.green().bold());

    // decryption
    print!("6. Decryption... ");
    let now = SystemTime::now();
    let res = sk.decrypt(&ct_max);
    let time = now.elapsed().unwrap().as_millis() as f64 / 1000.;
    let s_time = format!("{} s", time);
    println!("{}", s_time.green().bold());

    // max result
    let s_res = format!("{} mod 8", res);
    println!(
        "-> Output of the circuit (should be 7): {}",
        s_res.blue().bold()
    );
}
