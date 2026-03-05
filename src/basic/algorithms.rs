use crate::basic::utils;
use num_bigint::{BigUint, RandBigInt};
use std::ops::{Add, Mul};
use num_traits::One;
use crate::basic::utils::{is_coprime, TWO};

/// Encrypts the bits of a String using a linear formula
pub fn affine_encryption(input: &BigUint, m: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    // Encrypt
    input.mul(m).add(b) % modulus
}

/// Decrypts the bits of an encrypted String using an inversed linear formula
pub fn affine_decryption(input: &BigUint, m: &BigUint, b: &BigUint, modulus: &BigUint, debug: bool) -> BigUint {
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
pub fn get_affine_modulus(input: &String) -> BigUint {
    let bit_size = input.len() * 8;
    BigUint::one() << bit_size
}

/// Encrypts the plaintext by adding a repeated key to the UTF-8 value of each character
pub fn vigenere_encryption(mut input_chars: &mut Vec<char>, key_chars: &Vec<char>) -> String {
    // Create cipher by adding strings
    add_strings(&mut input_chars, &key_chars);
    chars_to_str(&input_chars)
}

/// Decrypts the plaintext by subtracting a repeated key's UTF-8 value from each character
pub fn vigenere_decryption(mut input_chars: &mut Vec<char>, key_chars: &Vec<char>) -> String {
    sub_strings(&mut input_chars, &key_chars);
    chars_to_str(&input_chars)
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
    let (p, q, n) = generate_rsa_primes(&m);
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
    c.modpow(&d, &n)
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