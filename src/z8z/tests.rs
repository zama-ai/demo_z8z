use crate::z8z::*;
use concrete_lib::core_api::math::Random;

#[allow(unused_macros)]
macro_rules! random_index {
    ($max: expr) => {{
        if $max == 0 {
            (0 as usize)
        } else {
            let mut rs = vec![0 as u32; 1];
            Random::rng_uniform(&mut rs);
            (rs[0] % ($max as u32)) as usize
        }
    }};
}

fn test_encrypt_decrypt(i: usize, sk: &SecretKey) -> usize {
    // generate random messages
    let m = random_index!(MOD);

    // encryption
    let ct = sk.encrypt(m);

    // decryption
    let m_dec: usize = sk.decrypt(&ct);

    // test
    if m % MOD != m_dec {
        println!(
            "test_encrypt_decrypt[{}]: {} != {} (obtained after decryption)",
            i,
            m % MOD,
            m_dec
        );
        return 1;
    }
    0
}

fn test_add(i: usize, sk: &SecretKey, hek: &HomomorphicKey) -> usize {
    // generate random messages
    let m1 = random_index!(MOD);
    let m2 = random_index!(MOD);

    // encryption
    let ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    let ct3 = hek.add(&ct1, &ct2);

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if (m1 + m2) % MOD != m {
        println!(
            "test_add[{}]: {} + {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 + m2) % MOD,
            m
        );
        return 1;
    }
    0
}

fn test_add_cst(i: usize, sk: &SecretKey, hek: &HomomorphicKey) -> usize {
    // generate random messages
    let m1 = random_index!(MOD);
    let m2 = random_index!(MOD);

    // encryption
    let ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    let ct3 = hek.add(&ct1, m2);

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if (m1 + m2) % MOD != m {
        println!(
            "test_add_cst[{}]: {} + {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 + m2) % MOD,
            m
        );
        return 1;
    }
    0
}

fn test_add_inplace(i: usize, sk: &SecretKey, hek: &HomomorphicKey) -> usize {
    // generate random messages
    let m1 = random_index!(MOD);
    let m2 = random_index!(MOD);

    // encryption
    let mut ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    hek.add_inplace(&mut ct1, &ct2);

    // decryption
    let m: usize = sk.decrypt(&ct1);

    // test
    if (m1 + m2) % MOD != m {
        println!(
            "test_add_inplace[{}]: {} + {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 + m2) % MOD,
            m
        );
        return 1;
    }
    0
}

fn test_add_cst_inplace(i: usize, sk: &SecretKey, hek: &HomomorphicKey) -> usize {
    // generate random messages
    let m1 = random_index!(MOD);
    let m2 = random_index!(MOD);

    // encryption
    let mut ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    hek.add_inplace(&mut ct1, m2);

    // decryption
    let m: usize = sk.decrypt(&ct1);

    // test
    if (m1 + m2) % MOD != m {
        println!(
            "test_add_cst_inplace[{}]: {} + {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 + m2) % MOD,
            m
        );
        return 1;
    }
    0
}

fn test_sub(i: usize, sk: &SecretKey, hek: &HomomorphicKey) -> usize {
    // generate random messages
    let m1 = random_index!(MOD);
    let m2 = random_index!(MOD);

    // encryption
    let ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    let ct3 = hek.sub(&ct1, &ct2);

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if (m1 - m2) % MOD != m {
        println!(
            "test_sub[{}]: {} - {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 - m2) % MOD,
            m
        );
        return 1;
    }
    0
}

fn test_sub_cst(i: usize, sk: &SecretKey, hek: &HomomorphicKey) -> usize {
    // generate random messages
    let m1 = random_index!(MOD);
    let m2 = random_index!(MOD);

    // encryption
    let ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    let ct3 = hek.sub(&ct1, m2);

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if (m1 - m2) % MOD != m {
        println!(
            "test_sub_cst[{}]: {} - {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 - m2) % MOD,
            m
        );
        return 1;
    }
    0
}

fn test_sub_inplace(i: usize, sk: &SecretKey, hek: &HomomorphicKey) -> usize {
    // generate random messages
    let m1 = random_index!(MOD);
    let m2 = random_index!(MOD);

    // encryption
    let mut ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    hek.sub_inplace(&mut ct1, &ct2);

    // decryption
    let m: usize = sk.decrypt(&ct1);

    // test
    if (m1 - m2) % MOD != m {
        println!(
            "test_sub_inplace[{}]: {} - {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 - m2) % MOD,
            m
        );
        return 1;
    }
    0
}

fn test_sub_cst_inplace(i: usize, sk: &SecretKey, hek: &HomomorphicKey) -> usize {
    // generate random messages
    let m1 = random_index!(MOD);
    let m2 = random_index!(MOD);

    // encryption
    let mut ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    hek.sub_inplace(&mut ct1, m2);

    // decryption
    let m: usize = sk.decrypt(&ct1);

    // test
    if (m1 - m2) % MOD != m {
        println!(
            "test_sub_cst_inplace[{}]: {} - {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 - m2) % MOD,
            m
        );
        return 1;
    }
    0
}

fn test_mul_cst(i: usize, sk: &SecretKey, hek: &HomomorphicKey) -> usize {
    // generate random messages
    let m1 = random_index!(MOD);
    let m2 = random_index!(MOD);

    // encryption
    let ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    let ct3 = hek.mul(&ct1, m2);

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if (m1 * m2) % MOD != m {
        println!(
            "test_mul_cst[{}]: {} * {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 * m2) % MOD,
            m
        );
        return 1;
    }
    0
}

fn test_mul_cst_inplace(i: usize, sk: &SecretKey, hek: &HomomorphicKey) -> usize {
    // generate random messages
    let m1 = random_index!(MOD);
    let m2 = random_index!(MOD);

    // encryption
    let mut ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    hek.mul_inplace(&mut ct1, m2);

    // decryption
    let m: usize = sk.decrypt(&ct1);

    // test
    if (m1 * m2) % MOD != m {
        println!(
            "test_mul_cst_inplace[{}]: {} * {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 * m2) % MOD,
            m
        );
        return 1;
    }
    0
}

fn test_mul(i: usize, sk: &SecretKey, hek: &HomomorphicKey) -> usize {
    // generate random messages
    let m1 = random_index!(MOD);
    let m2 = random_index!(MOD);

    // encryption
    let ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    let ct3 = hek.mul(&ct1, &ct2);

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if (m1 * m2) % MOD != m {
        println!(
            "test_mul[{}]: {} * {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 * m2) % MOD,
            m
        );
        return 1;
    }
    0
}

fn test_mul_inplace(i: usize, sk: &SecretKey, hek: &HomomorphicKey) -> usize {
    // generate random messages
    let m1 = random_index!(MOD);
    let m2 = random_index!(MOD);

    // encryption
    let mut ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    hek.mul_inplace(&mut ct1, &ct2);

    // decryption
    let m: usize = sk.decrypt(&ct1);

    // test
    if (m1 * m2) % MOD != m {
        println!(
            "test_mul_inplace[{}]: {} * {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 * m2) % MOD,
            m
        );
        return 1;
    }
    0
}

fn test_max(i: usize, sk: &SecretKey, hek: &HomomorphicKey) -> usize {
    // generate random messages
    let m1 = random_index!(MOD);
    let m2 = random_index!(MOD);

    // encryption
    let ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    let ct3 = hek.max(&ct1, &ct2);

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if usize::max(m1, m2) != m {
        println!(
            "test_max[{}]: max({}, {}) = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            usize::max(m1, m2),
            m
        );
        return 1;
    }
    0
}

#[test]
fn test_homomorphic_key() {
    let (sk, hek) = setup();
    // let (sk, hek) = z8z::setup_load();
    let mut cpt: usize = 0;

    for i in 0..100 {
        cpt += test_encrypt_decrypt(i, &sk);
        cpt += test_add(i, &sk, &hek);
        cpt += test_add_inplace(i, &sk, &hek);
        cpt += test_add_cst(i, &sk, &hek);
        cpt += test_add_cst_inplace(i, &sk, &hek);
        cpt += test_sub(i, &sk, &hek);
        cpt += test_sub_inplace(i, &sk, &hek);
        cpt += test_sub_cst(i, &sk, &hek);
        cpt += test_sub_cst_inplace(i, &sk, &hek);
        cpt += test_mul_cst(i, &sk, &hek);
        cpt += test_mul_cst_inplace(i, &sk, &hek);
        cpt += test_mul(i, &sk, &hek);
        cpt += test_mul_inplace(i, &sk, &hek);
        cpt += test_max(i, &sk, &hek);
    }
    if cpt != 0 {
        panic!("{} ERROR(S)!", cpt);
    }
}
