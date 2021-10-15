use crate::PARAMS;
use crate::zqz;
use crate::zqz::keys::EncryptKey;
use concrete_core::math::{
    random::{
        RandomGenerator,
    },
    tensor::{
        Tensor
    },
};

#[allow(unused_macros)]
macro_rules! random_index {
    ($max: expr) => {{
        if $max == 0 {
            (0 as usize)
        } else {
            let mut rs = Tensor::allocate(0, 1);
            RandomGenerator::new(None).fill_tensor_with_random_uniform(&mut rs);
            (rs.get_element(0) % ($max as u32)) as usize
        }
    }};
}

fn test_encrypt_decrypt(i: usize, sk: &EncryptKey) -> usize {
    // generate random messages
    let m = random_index!(PARAMS.modulo);

    // encryption
    let ct = sk.encrypt(m);

    // decryption
    let m_dec: usize = sk.decrypt(&ct);

    // test
    if m % PARAMS.modulo != m_dec {
        println!(
            "test_encrypt_decrypt[{}]: {} != {} (obtained after decryption)",
            i,
            m % PARAMS.modulo,
            m_dec
        );
        return 1;
    }
    0
}

fn test_add(i: usize, sk: &EncryptKey) -> usize {
    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    let ct3 = &ct1 + &ct2;

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if (m1 + m2) % PARAMS.modulo != m {
        println!(
            "test_add[{}]: {} + {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 + m2) % PARAMS.modulo,
            m
        );
        return 1;
    }
    0
}

fn test_add_cst(i: usize, sk: &EncryptKey) -> usize {
    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    let ct3 = &ct1 + m2;

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if (m1 + m2) % PARAMS.modulo != m {
        println!(
            "test_add_cst[{}]: {} + {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 + m2) % PARAMS.modulo,
            m
        );
        return 1;
    }
    0
}

fn test_add_inplace(i: usize, sk: &EncryptKey) -> usize {
    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let mut ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    ct1 += &ct2;

    // decryption
    let m: usize = sk.decrypt(&ct1);

    // test
    if (m1 + m2) % PARAMS.modulo != m {
        println!(
            "test_add_inplace[{}]: {} + {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 + m2) % PARAMS.modulo,
            m
        );
        return 1;
    }
    0
}

fn test_add_cst_inplace(i: usize, sk: &EncryptKey) -> usize {
    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let mut ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    ct1 += m2;

    // decryption
    let m: usize = sk.decrypt(&ct1);

    // test
    if (m1 + m2) % PARAMS.modulo != m {
        println!(
            "test_add_cst_inplace[{}]: {} + {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 + m2) % PARAMS.modulo,
            m
        );
        return 1;
    }
    0
}

fn test_sub(i: usize, sk: &EncryptKey) -> usize {
    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    let ct3 = &ct1 - &ct2;

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if (PARAMS.modulo + m1 - m2) % PARAMS.modulo != m {
        println!(
            "test_sub[{}]: {} - {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (PARAMS.modulo + m1 - m2) % PARAMS.modulo,
            m
        );
        return 1;
    }
    0
}

fn test_sub_cst(i: usize, sk: &EncryptKey) -> usize {
    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    let ct3 = &ct1 - m2;

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if (PARAMS.modulo + m1 - m2) % PARAMS.modulo != m {
        println!(
            "test_sub_cst[{}]: {} - {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (PARAMS.modulo + m1 - m2) % PARAMS.modulo,
            m
        );
        return 1;
    }
    0
}

fn test_sub_inplace(i: usize, sk: &EncryptKey) -> usize {
    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let mut ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    ct1 -= &ct2;

    // decryption
    let m: usize = sk.decrypt(&ct1);

    // test
    if (PARAMS.modulo + m1 - m2) % PARAMS.modulo != m {
        println!(
            "test_sub_inplace[{}]: {} - {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (PARAMS.modulo + m1 - m2) % PARAMS.modulo,
            m
        );
        return 1;
    }
    0
}

fn test_sub_cst_inplace(i: usize, sk: &EncryptKey) -> usize {
    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let mut ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    ct1 -= m2;

    // decryption
    let m: usize = sk.decrypt(&ct1);

    // test
    if (PARAMS.modulo + m1 - m2) % PARAMS.modulo != m {
        println!(
            "test_sub_cst_inplace[{}]: {} - {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (PARAMS.modulo + m1 - m2) % PARAMS.modulo,
            m
        );
        return 1;
    }
    0
}

fn test_mul_cst(i: usize, sk: &EncryptKey) -> usize {
    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    let ct3 = &ct1 * m2;

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if (m1 * m2) % PARAMS.modulo != m {
        println!(
            "test_mul_cst[{}]: {} * {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 * m2) % PARAMS.modulo,
            m
        );
        return 1;
    }
    0
}

fn test_mul_cst_inplace(i: usize, sk: &EncryptKey) -> usize {
    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let mut ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    ct1 *= m2;

    // decryption
    let m: usize = sk.decrypt(&ct1);

    // test
    if (m1 * m2) % PARAMS.modulo != m {
        println!(
            "test_mul_cst_inplace[{}]: {} * {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 * m2) % PARAMS.modulo,
            m
        );
        return 1;
    }
    0
}

fn test_mul(i: usize, sk: &EncryptKey) -> usize {
    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    let ct3 = &ct1 * &ct2;

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if (m1 * m2) % PARAMS.modulo != m {
        println!(
            "test_mul[{}]: {} * {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 * m2) % PARAMS.modulo,
            m
        );
        return 1;
    }
    0
}

fn test_mul_inplace(i: usize, sk: &EncryptKey) -> usize {
    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let mut ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    ct1 *= &ct2;

    // decryption
    let m: usize = sk.decrypt(&ct1);

    // test
    if (m1 * m2) % PARAMS.modulo != m {
        println!(
            "test_mul_inplace[{}]: {} * {} = {} != {} (obtained after decryption)",
            i,
            m1,
            m2,
            (m1 * m2) % PARAMS.modulo,
            m
        );
        return 1;
    }
    0
}

fn test_max(i: usize, sk: &EncryptKey) -> usize {
    use zqz::max::max;

    // generate random messages
    let m1 = 0; //random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let ct1 = sk.encrypt(m1);
    let ct2 = sk.encrypt(m2);

    // homomorphic evaluation
    let ct3 = max(&ct1, &ct2);

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

fn test_max_cst(i: usize, sk: &EncryptKey) -> usize {
    use zqz::max::max;

    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    let ct3 = max(&ct1, m2);

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if usize::max(m1, m2) != m {
        println!(
            "test_max_cst[{}]: max({}, {}) = {} != {} (obtained after decryption)",
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

fn test_max_cst_rev(i: usize, sk: &EncryptKey) -> usize {
    use zqz::max::max;

    // generate random messages
    let m1 = random_index!(PARAMS.modulo);
    let m2 = random_index!(PARAMS.modulo);

    // encryption
    let ct1 = sk.encrypt(m1);

    // homomorphic evaluation
    let ct3 = max(m2, &ct1);

    // decryption
    let m: usize = sk.decrypt(&ct3);

    // test
    if usize::max(m1, m2) != m {
        println!(
            "test_max_cst_rev[{}]: max({}, {}) = {} != {} (obtained after decryption)",
            i,
            m2,
            m1,
            usize::max(m1, m2),
            m
        );
        return 1;
    }
    0
}

#[test]
fn test_homomorphic_key() {
    let sk = if !EncryptKey::keys_exist(&PARAMS.gen_prefix()) {
        let key = EncryptKey::new();
        key.save_to_files(&PARAMS.gen_prefix());
        key
    } else {
        EncryptKey::load_from_files(&PARAMS.gen_prefix())
    };

    // let sk = zqz::setup_load();
    let mut cpt: usize = 0;

    for i in 0..100 {
        cpt += test_encrypt_decrypt(i, &sk);
        cpt += test_add(i, &sk);
        cpt += test_add_inplace(i, &sk);
        cpt += test_add_cst(i, &sk);
        cpt += test_add_cst_inplace(i, &sk);
        cpt += test_sub(i, &sk);
        cpt += test_sub_inplace(i, &sk);
        cpt += test_sub_cst(i, &sk);
        cpt += test_sub_cst_inplace(i, &sk);
        cpt += test_mul_cst(i, &sk);
        cpt += test_mul_cst_inplace(i, &sk);
        cpt += test_mul(i, &sk);
        cpt += test_mul_inplace(i, &sk);
        cpt += test_max(i, &sk);
        cpt += test_max_cst(i, &sk);
        cpt += test_max_cst_rev(i, &sk);
    }
    if cpt != 0 {
        panic!("{} ERROR(S)!", cpt);
    }
}
