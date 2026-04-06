use crate::basic::utils;
use crate::basic::utils::{FOUR, TWO, is_coprime};
use num_bigint::{BigUint, RandBigInt, ToBigInt};
use num_traits::One;
use std::ops::{Add, Mul};

/// Encrypts the bits of a String using a linear formula
pub fn affine_encryption(input: &BigUint, m: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    // Encrypt
    input.mul(m).add(b) % modulus
}

/// Decrypts the bits of an encrypted String using an inversed linear formula
pub fn affine_decryption(
    input: &BigUint,
    m: &BigUint,
    b: &BigUint,
    modulus: &BigUint,
    debug: bool,
) -> BigUint {
    let inv_b = utils::wrapping_neg(b, modulus);
    if let Some(inv_m) = utils::extended_euclidean_algorithm(modulus, m) {
        let decrypted_b = inv_b.mul(&inv_m) % modulus;
        input.mul(inv_m).add(decrypted_b) % modulus
    } else {
        if debug {
            println!("{} is not invertible", m);
        }
        BigUint::ZERO
    }
}

/// Gets the modulus for Affine Encryption based on the String length (in bits)
pub fn get_affine_modulus(input: &str) -> BigUint {
    let bit_size = input.len() * 8;
    BigUint::one() << bit_size
}

/// Encrypts the plaintext by adding a repeated key to the UTF-8 value of each character
pub fn vigenere_encryption(input_chars: &mut [char], key_chars: &[char]) -> String {
    // Create cipher by adding strings
    add_strings(input_chars, key_chars);
    chars_to_str(input_chars)
}

/// Decrypts the plaintext by subtracting a repeated key's UTF-8 value from each character
pub fn vigenere_decryption(input_chars: &mut [char], key_chars: &[char]) -> String {
    sub_strings(input_chars, key_chars);
    chars_to_str(input_chars)
}

/// str1 is the plaintext and str2 is the key
fn add_strings(str1: &mut [char], str2: &[char]) {
    for (i, byte) in str1.iter_mut().enumerate() {
        let mut char_val = *byte as u32;
        char_val = char_val.wrapping_add(u32::from(str2[i % str2.len()]));
        *byte = char::from_u32(char_val).unwrap();
    }
}

/// str1 is the plaintext and str2 is the key
fn sub_strings(str1: &mut [char], str2: &[char]) {
    for (i, byte) in str1.iter_mut().enumerate() {
        let mut char_val = *byte as u32;
        char_val = char_val.wrapping_sub(u32::from(str2[i % str2.len()]));
        *byte = char::from_u32(char_val).unwrap();
    }
}

/// Converts a series of characters into a String
fn chars_to_str(chars: &[char]) -> String {
    String::from_iter(chars.iter())
}

/// Encrypts an integer using RSA encryption
pub fn rsa_encrypt(m: &BigUint, debug: bool) -> (BigUint, BigUint, BigUint) {
    let (p, q, n) = generate_rsa_primes(m);
    let phi = (&p - BigUint::one()) * (&q - BigUint::one());
    let e = generate_coprime(&phi);
    if debug {
        println!("N: {}", n);
        println!("E: {}", e);
    }

    if let Some(d) = utils::extended_euclidean_algorithm(&phi, &e) {
        (m.modpow(&e, &n), d, n)
    } else {
        if debug {
            println!("{} is not invertible", e);
        }
        (BigUint::ZERO, BigUint::ZERO, n)
    }
}

/// Decrypts an RSA encryption
pub fn rsa_decrypt(c: &BigUint, d: &BigUint, n: &BigUint) -> BigUint {
    // Decrypt text
    c.modpow(d, n)
}

/// Generates the primes p and q, and also calculates N
fn generate_rsa_primes(m: &BigUint) -> (BigUint, BigUint, BigUint) {
    let mut sqrt_m = m.sqrt();

    loop {
        let p = utils::next_prime(&mut sqrt_m);
        let q = utils::next_prime(&mut sqrt_m);

        let n = &p * &q;

        if n > *m {
            return (p, q, n);
        }
    }
}

/// Generates a coprime value for the public encryption key
fn generate_coprime(prime: &BigUint) -> BigUint {
    loop {
        let mut rng = rand::thread_rng();
        let lower: &BigUint = &TWO;
        let upper: &BigUint = prime;
        let random = rng.gen_biguint_range(lower, upper);
        if is_coprime(&random, prime) {
            return random;
        }
    }
}

/// Simplified implementation of the Diffie-Hellman key exchange. It uses safe primes to ensure
/// that the selected values are cryptographically secure. It computes the generation of safe primes
/// in parallel to reduce runtime.
pub fn diffie_hellman(bits: u64) -> (BigUint, BigUint) {
    let (p, q) = utils::generate_safe_prime(bits);

    let mut rng = rand::thread_rng();

    let a = rng.gen_biguint_below(&q);
    let b = rng.gen_biguint_below(&q);

    let big_a = TWO.modpow(&a, &p);
    let big_b = TWO.modpow(&b, &p);

    let key1 = big_b.modpow(&a, &p);
    let key2 = big_a.modpow(&b, &p);

    assert_eq!(key1, key2);

    (key1, key2)
}

/// The Rabin Cryptosystem uses Blum Primes and the Extended Euclidean Algorithm to create a
/// mathematically-proven cryptosystem for sharing information securely. It relies on
/// quadratic residues to produce these secure keys.
pub fn rabin(input: &[u8]) -> (BigUint, BigUint) {
    let m_original_bytes = utils::extend_binary(input);
    let m_original = BigUint::from_bytes_le(&m_original_bytes);

    // Choose N so that m_original < n
    let m_bits = m_original.bits();
    let n_bits = m_bits + 16;
    let p_bits = n_bits / 2;
    let q_bits = n_bits - p_bits;

    // Key generation
    let p = utils::blum_prime_generator(p_bits);
    let q = utils::blum_prime_generator(q_bits);
    let n = &p * &q;
    assert!(m_original < n, "n is too small!");

    // Encryption
    let c = m_original.modpow(&TWO, &n);

    // Decryption
    // EEA
    let p_pre = (&p + BigUint::one()) / &*FOUR;
    let p1 = c.modpow(&p_pre, &p);
    let p2 = &p - &p1;

    let q_pre = (&q + BigUint::one()) / &*FOUR;
    let q1 = c.modpow(&q_pre, &q);
    let q2 = &q - &q1;

    let (_, y_p, y_q) = utils::gcd_extended(&p.to_bigint().unwrap(), &q.to_bigint().unwrap());
    let p = p.to_bigint().unwrap();
    let q = q.to_bigint().unwrap();
    let p1 = p1.to_bigint().unwrap();
    let p2 = p2.to_bigint().unwrap();
    let q1 = q1.to_bigint().unwrap();
    let q2 = q2.to_bigint().unwrap();
    let n = n.to_bigint().unwrap();

    // Chinese Remainder Theorem
    let d1 = (&y_p * &p * &q1) + (&y_q * &q * &p1);
    let d1 = utils::mod_floor(&d1, &n);
    println!("d1 is {}", d1);
    let d1_bytes = d1.to_bytes_le();
    if utils::is_crt_output(&d1_bytes) {
        let output = BigUint::from_bytes_le(utils::from_extended_binary(&d1_bytes));
        return (c, output);
    }

    let d2 = (&y_p * &p * &q2) + (&y_q * &q * &p1);
    let d2 = utils::mod_floor(&d2, &n);
    println!("d2 is {}", d2);
    let d2_bytes = &*d2.to_bytes_le();
    if utils::is_crt_output(d2_bytes) {
        let output = BigUint::from_bytes_le(utils::from_extended_binary(d2_bytes));
        return (c, output);
    }

    let d3 = (&y_p * &p * &q1) + (&y_q * &q * &p2);
    let d3 = utils::mod_floor(&d3, &n);
    println!("d3 is {}", d3);
    let d3_bytes = &*d3.to_bytes_le();
    if utils::is_crt_output(d3_bytes) {
        let output = BigUint::from_bytes_le(utils::from_extended_binary(d3_bytes));
        return (c, output);
    }

    let d4 = (&y_p * &p * &q2) + (&y_q * &q * &p2);
    let d4 = utils::mod_floor(&d4, &n);
    println!("d4 is {}", d4);
    let d4_bytes = &*d4.to_bytes_le();
    if utils::is_crt_output(d4_bytes) {
        let output = BigUint::from_bytes_le(utils::from_extended_binary(d4_bytes));
        return (c, output);
    }

    (c, BigUint::ZERO)
}

/// The Goldwasser Micali is a proven cryptographically secure data exchange algorithm
/// that relies on quadratic residues' difficulty in factoring (prime factorization).
/// This cryptosystem is rarely used as the encrypted data is often significantly larger than
/// the inputted data, which can cause issues when sending data over the internet.
pub fn goldwasser_micali(input: &[u8]) -> (BigUint, String) {
    let m_original = BigUint::from_bytes_le(input);

    // Choose N so that m_original < n
    let m_bits = m_original.bits();
    let n_bits = m_bits + 16;
    let p_bits = n_bits / 2;
    let q_bits = n_bits - p_bits;

    // Key generation
    let p = utils::blum_prime_generator(p_bits);
    let q = utils::blum_prime_generator(q_bits);
    let n = &p * &q;
    assert!(m_original < n, "n is too small!");

    // Encryption
    let x = &n - BigUint::one(); // This is ok because Blum Integers are used
    let mut encrypted: Vec<BigUint> = Vec::new();
    for byte in input {
        let bits = utils::u8_to_bits_le(*byte);
        for &bit in &bits {
            let y = utils::random_unit_mod_n(&n);
            let x_pow = if bit == 0 { BigUint::one() } else { x.clone() };
            encrypted.push((y.modpow(&2u32.into(), &n) * x_pow) % &n);
        }
    }

    // Visual representation only
    let encrypted_val = utils::concat_biguints(&encrypted);

    // Decryption
    let mut bytes: Vec<u8> = Vec::new();
    let mut bits: [u8; 8] = [0; 8];
    let mut i = 0;

    for c in &encrypted {
        let bit = if c.modpow(&((&p - BigUint::one()) / 2u32), &p) == BigUint::one()
            && c.modpow(&((&q - BigUint::one()) / 2u32), &q) == BigUint::one()
        {
            0
        } else {
            1
        };

        bits[i] = bit;
        i += 1;

        if i == 8 {
            bytes.push(utils::bits_to_u8_le(bits));
            bits = [0; 8];
            i = 0;
        }
    }

    if i > 0 {
        let mut last_byte = 0u8;
        for j in 0..i {
            last_byte |= bits[j] << j;
        }
        bytes.push(last_byte);
    }

    let decrypted_str = String::from_utf8(bytes).unwrap();

    (encrypted_val, decrypted_str)
}
