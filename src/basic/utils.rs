use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use num_rational::BigRational;
use num_traits::{One, Signed, ToPrimitive, Zero};
use std::mem::swap;
use std::ops::{AddAssign, Div, Mul, Sub};
use std::sync::LazyLock;
use rayon::prelude::*;

pub static TWO: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(2_u32));
pub static THREE: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(3_u32));
pub static FIVE: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(5_u32));
pub static SIX: LazyLock<BigUint> = LazyLock::new(|| BigUint::from(6_u32));

const SMALL_PRIMES: [u64; 32] = [
    3,5,7,11,13,17,19,23,29,31,
    37,41,43,47,53,59,61,67,
    71,73,79,83,89,97,
    101,103,107,109,113,127,131,137
];

const WHEEL_RESIDUES: [u64; 8] = [1, 7, 11, 13, 17, 19, 23, 29];
const WHEEL_STEPS: [u64; 8] = [6,4,2,4,2,4,6,2];
const WHEEL_SIZE: usize = 8;

const BATCH: usize = 4096;

/// Gets the next prime with a 2^-80 inaccuracy (cryptographically secure)
pub fn next_prime(n: &mut BigUint) -> BigUint {
    if &*n < &*TWO {
        return TWO.clone();
    }

    *n += BigUint::one();

    if &*n % &*TWO == BigUint::ZERO {
        *n += BigUint::one();
    }

    loop {
        if is_probably_prime(&n, 40) {
            return n.clone();
        }
        *n += &*TWO;
    }
}

/// Generates a prime value with the given number of bits
pub fn generate_prime(bits: u64) -> BigUint {
    let mut rng = rand::thread_rng();

    loop {
        let mut candidate = rng.gen_biguint(bits);

        // Force correct bit size
        candidate.set_bit(bits - 1, true);

        // Force odd
        candidate.set_bit(0, true);

        // Small prime filter
        let mut divisible = false;
        for p in SMALL_PRIMES {
            if (&candidate % p).is_zero() {
                divisible = true;
                break;
            }
        }

        if divisible {
            continue;
        }

        if is_probably_prime(&candidate, 40) {
            return candidate;
        }
    }
}

/// Implement square root for BigRational
pub fn sqrt(q: &BigRational) -> Option<BigRational> {
    if q.is_negative() {
        return None; // Square root of a negative rational is imaginary
    }

    let num = q.numer();
    let den = q.denom();

    // Check if numerator and denominator have exact integer square roots
    let sqrt_num_candidate = num.sqrt();
    let sqrt_den_candidate = den.sqrt();

    // Verify they are perfect squares
    if &(&sqrt_num_candidate * &sqrt_num_candidate) == num && &(&sqrt_den_candidate * &sqrt_den_candidate) == den {
        Some(BigRational::new(sqrt_num_candidate, sqrt_den_candidate))
    } else {
        None
    }
}

/// Fast modular exponentiation
#[inline]
fn mod_pow(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    base.modpow(exp, modulus)
}

/// Miller–Rabin primality test
fn is_probably_prime(n: &BigUint, rounds: u32) -> bool {
    if *n < *TWO {
        return false;
    }

    // Small primes check
    for &p in &SMALL_PRIMES {
        let p_big = BigUint::from(p);
        if *n == p_big {
            return true;
        }
        if n % &p_big == BigUint::ZERO {
            return false;
        }
    }

    // Write n-1 = d * 2^r
    let mut d = n - BigUint::one();
    let mut r = 0u32;

    while &d % &*TWO == BigUint::ZERO {
        d /= &*TWO;
        r += 1;
    }

    for _ in 0..rounds {
        let a = rand::thread_rng().gen_biguint_range(&*TWO, &(n - &*TWO));
        let mut x = mod_pow(&a, &d, n);

        if x == BigUint::one() || x == n - BigUint::one() {
            continue;
        }

        let mut composite = true;

        for _ in 0..(r - 1) {
            x = mod_pow(&x, &*TWO, n);
            if x == n - BigUint::one() {
                composite = false;
                break;
            }
        }

        if composite {
            return false;
        }
    }

    true
}

/// Generates 2 safe primes. A safe prime is any prime that takes the form of 2q+1 where q is a
/// Sophie Germain prime. These primes are extremely resilient to cryptographical attacks.
/// These primes are generated concurrently to reduce runtime.
pub fn generate_safe_prime(bits: u64) -> (BigUint, BigUint) {
    loop {
        let result = (0..rayon::current_num_threads())
            .into_par_iter()
            .map(|_| try_safe_prime(bits))
            .find_any(|x| x.is_some());

        if let Some(Some(pair)) = result {
            return pair;
        }
    }
}

fn try_safe_prime(bits: u64) -> Option<(BigUint, BigUint)> {
    let mut rng = rand::thread_rng();

    let mut base = rng.gen_biguint(bits - 1);
    base.set_bit(bits - 2, true);
    base.set_bit(0, true);

    let (aligned, wheel_idx) = align_to_wheel(base);

    let candidates = sieve_batch(&aligned, wheel_idx);

    for q in candidates {

        if !is_probably_prime(&q, 8) {
            continue;
        }

        let p = &q * 2u32 + 1u32;

        if is_probably_prime(&p, 8) {
            return Some((p, q));
        }
    }

    None
}

/// Batches many potential prime numbers together and checks them in parallel
fn sieve_batch(base: &BigUint, start_idx: usize) -> Vec<BigUint> {
    let mut alive = vec![true; BATCH];

    let mut residues: Vec<u64> = SMALL_PRIMES
        .iter()
        .map(|&p| (base % p).to_u64().unwrap())
        .collect();

    let mut idx = start_idx;

    for i in 0..BATCH {

        for (j, &p) in SMALL_PRIMES.iter().enumerate() {
            if residues[j] == 0 {
                alive[i] = false;
            }

            // Skip some computations
            residues[j] += WHEEL_STEPS[idx];
            if residues[j] >= p {
                residues[j] %= p;
            }
        }

        idx += 1;
        if idx == WHEEL_SIZE {
            idx = 0;
        }
    }

    let mut results = Vec::new();

    let mut q = base.clone();
    let mut idx = start_idx;

    for i in 0..BATCH {
        if alive[i] {
            results.push(q.clone());
        }

        q += WHEEL_STEPS[idx];

        idx += 1;
        if idx == WHEEL_SIZE {
            idx = 0;
        }
    }

    results
}

fn align_to_wheel(mut q: BigUint) -> (BigUint, usize) {
    let r = (&q % 30u32).to_u64_digits()[0];

    for (i, residue) in WHEEL_RESIDUES.iter().enumerate() {
        if *residue >= r {
            let diff = residue - r;
            q += diff;
            return (q, i);
        }
    }

    q += (30 - r) + WHEEL_RESIDUES[0];
    (q, 0)
}

/// The Extended Euclidean Algorithm (EEA) can be used to compute the modular inverses
/// of integers.
/// Let m be the modulo value and i value being inversed.
pub fn extended_euclidean_algorithm(m: &BigUint, i: &BigUint) -> Option<BigUint> {
    let mut t = BigInt::ZERO;
    let mut new_t = BigInt::one();

    let mut r = m.to_bigint().unwrap();
    let mut new_r = i.to_bigint().unwrap();

    while !new_r.is_zero() {
        let quotient = &r / &new_r;

        let temp_t = t - &quotient * &new_t;
        t = new_t;
        new_t = temp_t;

        let temp_r = &r - &quotient * &new_r;
        r = new_r;
        new_r = temp_r;
    }

    if r != BigInt::one() {
        return None; // Not invertible
    }

    if t < BigInt::ZERO {
        t += m.to_bigint().unwrap();
    }

    Some(t.to_biguint().unwrap())
}

/// Fast Exponentiation allows programs to calculate very large exponents without overflowing
/// because each step is modulo. It also reduces the number of computations by precomputing binary
/// powers. This implementation uses highly efficient bitwise operations to create an allocation-free
/// implementation
pub fn fast_exponentiation(
    base: &BigUint,
    exp: &BigUint,
    modulus: &BigUint,
) -> BigUint {
    if modulus.is_zero() {
        panic!("Modulus cannot be zero");
    }

    let mut result = BigUint::one();
    let mut base = base % modulus;
    let mut exp = exp.clone();

    while !exp.is_zero() {
        // If lowest bit is 1
        if exp.bit(0) {
            result = &result.mul(&base) % modulus;
        }

        // Shift exponent right
        exp >>= 1;

        // Square base
        base = (&base * &base) % modulus;
    }

    result
}

/// Calculates the greatest common divisor using the Extended Euclidean Algorithm
pub fn gcd(n: &BigUint, m: &BigUint) -> BigUint {
    let mut a = n.clone();
    let mut b = m.clone();

    if a.is_zero() || b.is_zero() {
        return BigUint::zero();
    }

    while !b.is_zero() {
        if b < a {
            swap(&mut a, &mut b);
        }
        b %= &a;
    }

    a
}

/// Encodes text as bytes and provides the BigUInt representation
pub fn encode_str(s: &str) -> BigUint {
    BigUint::from_bytes_le(s.as_bytes())
}

/// Decodes a BigUInt into bytes and parses it with UTF8
pub fn decode_str(n: &BigUint) -> String {
    let bytes = n.to_bytes_le();
    String::from_utf8(bytes).expect("Invalid UTF-8")
}

/// Converts an array of chars to a String
pub fn chars_to_str(chars: &[char]) -> String {
    String::from_iter(chars.iter())
}

/// Negates the value then takes the modulu to make it positive
pub fn wrapping_neg(x: &BigUint, modulus: &BigUint) -> BigUint {
    if x.is_zero() {
        BigUint::ZERO
    } else {
        modulus - (x % modulus)
    }
}

/// If the two value's GCD equals 1
pub fn is_coprime(a: &BigUint, b: &BigUint) -> bool {
    gcd(a, b) == BigUint::one()
}

/// Determines if a value is prime or not using a series of tests
pub fn is_prime(n: &BigUint) -> bool {
    // Corner cases
    if n <= &BigUint::one() {
        return false;
    }
    if n <= &*THREE {
        return true;
    }

    // This is checked so that we can skip
    // middle five numbers in below loop
    if (n % &*TWO).is_zero() || (n % &*THREE).is_zero() {
        return false;
    }

    let mut i= FIVE.clone();
    while &i * &i <= *n {
        if (n % &i).is_zero() || (n % (&i + &*TWO)).is_zero() {
            return false;
        }
        i += &*SIX;
    }
    true
}

/// Finds the prime factors of a value
pub fn find_prime_factors(factors: &mut Vec<BigUint>, n: &BigUint) {
    // Print the number of 2s that divide n
    let mut n_mut = n.clone();
    while (&n_mut % &*TWO).is_zero() {
        factors.push(TWO.clone());
        n_mut /= &*TWO;
    }

    // n must be odd at this point. So we can skip
    // one element (Note i = i +2)
    let mut i = THREE.clone();
    while &i <= &n_mut.sqrt() {
        while (&n_mut % &i).is_zero() {
            factors.push(i.clone());
            n_mut /= &i;
        }

        i.add_assign(&*TWO)
    }


    // This condition is to handle the case when
    // n is a prime number greater than 2
    if n_mut > *TWO {
        factors.push(n_mut.clone());
    }
}

/// Finds the smallest primitive root of a value greater than the greater_than value
pub fn find_primitive(n: &BigUint, greater_than: &BigUint) -> BigUint {
    let mut factors: Vec<BigUint> = Vec::new();
    let n_clone = &n.clone();

    // Check if n is prime or not
    if !is_prime(n_clone) {
        return BigUint::ZERO;
    }

    // Find value of Euler Totient function of n
    // Since n is a prime number, the value of Euler
    // Totient function is n-1 as there are n-1
    // relatively prime numbers.
    let phi = &n_clone.sub(BigUint::one());

    // Find prime factors of phi and store in a set
    find_prime_factors(&mut factors, &phi);

    // Check for every number from 2 to phi
    let mut r = TWO.clone();

    while &r <= phi {
        let mut flag = false;

        for factor in &factors {
            if r <= *greater_than || r.modpow(&phi.div(factor), &n_clone).is_one() {
                flag = true;
                break;
            }
        }

        if !flag {
            return r;
        }

        r += BigUint::one();
    }

    // If no primitive root found
    BigUint::ZERO
}

/// Recursive Extended Euclidean Algorithm
fn gcd_extended(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        return (b.clone(), BigInt::zero(), BigInt::one());
    }

    let (gcd, x1, y1) = gcd_extended(&(b % a), a);

    let x = &y1 - (b / a) * &x1;
    let y = x1;

    (gcd, x, y)
}

/// Computes the unique solution for a system of congruences
pub fn chinese_remainder_theorem(num: &[BigInt], modulo: &[BigInt]) -> BigInt {
    let mut prod = BigInt::one();

    for n in num {
        prod *= n;
    }

    let mut result = BigInt::ZERO;

    for i in 0..num.len() {
        let prod_i = &prod / &num[i];

        let (_, inv_i, _) = gcd_extended(&prod_i, &num[i]);

        result += &modulo[i] * &prod_i * inv_i;
    }

    ((result % &prod) + &prod) % &prod
}