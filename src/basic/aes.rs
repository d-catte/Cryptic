use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::prelude::ParallelSliceMut;

/// This is the substitution box (SBOX). This provides the randomness that makes AES
/// very hard to reverse without the key. Without this lookup table, the process
/// could easily be reversed using simple arithmetic.
/// It was generated using the Galois Field: GF(2^8)
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// This is the round constant lookup table.
/// This table ensures that each round of encryption/decryption is different
/// from the previous one. If two rounds were the same, they could be XORed
/// and the original key/data could be determined
const RCON: [[u8; 4]; 10] = [
    [0x01, 0, 0, 0],
    [0x02, 0, 0, 0],
    [0x04, 0, 0, 0],
    [0x08, 0, 0, 0],
    [0x10, 0, 0, 0],
    [0x20, 0, 0, 0],
    [0x40, 0, 0, 0],
    [0x80, 0, 0, 0],
    [0x1B, 0, 0, 0],
    [0x36, 0, 0, 0],
];

/// Rotates 4 bytes to the left, with the first byte being put on the end.
/// If this wasn't done, SBOX and RCON steps would be applied to the same byte
/// Ex: [0, 1, 2, 3] -> [1, 2, 3, 0]
fn rotword(w: [u8; 4]) -> [u8; 4] {
    [w[1], w[2], w[3], w[0]]
}

/// Applies the SBOX lookup to the bytes
fn subword(w: [u8; 4]) -> [u8; 4] {
    [
        SBOX[w[0] as usize],
        SBOX[w[1] as usize],
        SBOX[w[2] as usize],
        SBOX[w[3] as usize],
    ]
}

/// Applies an XOR mask of b bytes on a bytes
fn xor_bytes(a: &mut [u8], b: &[u8]) {
    for i in 0..a.len() {
        a[i] ^= b[i];
    }
}

/// This is the "encryption engine".
/// It schedules a pre-encryption phase to set up all values as encrypted,
/// then performs 14 additional rounds of encryption on the key to ensure they are
/// truly random.
///
/// Algorithm:
///
/// Every 8th Word (4 bytes):
/// - Rotate bytes to the left
/// - Swap bytes with SBOX
/// - XOR the value with a RCON constant
///
/// Every 4th Word (4 bytes):
/// - Swap bytes with SBOX
fn key_expansion_256(key: [u8; 32]) -> [[u8; 4]; 60] {
    let mut w = [[0u8; 4]; 60];

    // Copy the initial 256-bit key into the first 8 words
    for i in 0..8 {
        w[i] = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
    }

    for i in 8..60 {
        let mut temp = w[i - 1];
        if i % 8 == 0 {
            // Full transformation every 8 words
            temp = subword(rotword(temp));
            xor_bytes(&mut temp, &RCON[(i / 8) - 1]);
        } else if i % 8 == 4 {
            // Extra SubWord step specific to AES-256
            temp = subword(temp);
        }
        let mut xored = w[i - 8];
        xor_bytes(&mut xored, &temp);
        w[i] = xored;
    }
    w
}

struct Aes256 {
    round_keys: [[u8; 16]; 15],
}

impl Aes256 {
    /// Initializes the AES-256-bit encryption
    fn new(key: &[u8; 32]) -> Self {
        let expanded = key_expansion_256(*key);
        let mut round_keys = [[0u8; 16]; 15];

        for r in 0..15 {
            for word in 0..4 {
                let w = expanded[r * 4 + word];
                round_keys[r][word * 4..(word + 1) * 4].copy_from_slice(&w);
            }
        }

        Aes256 { round_keys }
    }

    /// Encrypts 1 4x4 matrix of bytes
    ///
    /// Steps:
    /// - XOR matrix with identity zero matrix
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.add_round_key(block, 0);
        for round in 1..14 {
            self.sub_bytes(block);
            Self::shift_rows(block);
            Self::mix_columns(block);
            self.add_round_key(block, round);
        }
        // Final round (No MixColumns)
        self.sub_bytes(block);
        Self::shift_rows(block);
        self.add_round_key(block, 14);
    }

    /// Performs rotword on an entire matrix
    fn shift_rows(state: &mut [u8; 16]) {
        let s = *state;
        // Row 1
        state[1] = s[5];
        state[5] = s[9];
        state[9] = s[13];
        state[13] = s[1];

        // Row 2
        state[2] = s[10];
        state[10] = s[2];
        state[6] = s[14];
        state[14] = s[6];

        // Row 3
        state[3] = s[15];
        state[15] = s[11];
        state[11] = s[7];
        state[7] = s[3];
    }

    /// Multiplies the value by 2 using a Galois Field of 256 (0 - 255).
    /// The value is XORed with 27 (0x1B) to simulate wrapping around 255
    fn gmul2(mut b: u8) -> u8 {
        let high_bit = b & 0x80;
        b <<= 1;
        if high_bit != 0 {
            b ^= 0x1B;
        } // AES polynomial
        b
    }

    /// This "blends" all 4 bytes in a column together to get a proper diffusion effect
    fn mix_columns(state: &mut [u8; 16]) {
        for i in 0..4 {
            let idx = i * 4;
            let a = state[idx];
            let b = state[idx + 1];
            let c = state[idx + 2];
            let d = state[idx + 3];

            state[idx] = Self::gmul2(a) ^ (Self::gmul2(b) ^ b) ^ c ^ d;
            state[idx + 1] = a ^ Self::gmul2(b) ^ (Self::gmul2(c) ^ c) ^ d;
            state[idx + 2] = a ^ b ^ Self::gmul2(c) ^ (Self::gmul2(d) ^ d);
            state[idx + 3] = (Self::gmul2(a) ^ a) ^ b ^ c ^ Self::gmul2(d);
        }
    }

    /// Substitutes the SBOX lookup values for each value in the matrix
    fn sub_bytes(&self, state: &mut [u8; 16]) {
        for chunk in state.chunks_exact_mut(4) {
            let word = [chunk[0], chunk[1], chunk[2], chunk[3]];
            chunk.copy_from_slice(&subword(word));
        }
    }

    /// Combines the current state with the round key using XOR.
    fn add_round_key(&self, state: &mut [u8; 16], round: usize) {
        let key = &self.round_keys[round];
        xor_bytes(state, key);
    }
}

/// Turns the AES encryption from a block cipher to a stream cipher.
/// This allows padding to be ignored since a complete 4x4 matrix of bytes isn't required.
/// This implementation encrypts the counter instead of encrypting the data directly.
///
/// - Initialize the Counter: Take the 12-byte Nonce and attach a 4-byte Counter (starting at 0) to make a full 16-byte block.
/// - Encrypt the Counter: Pass the Nonce + Counter block through the AES engine.
/// - The XOR Step: Take the output of that encryption and XOR it with the first 16 bytes of the message. This creates the ciphertext.
/// - Increment: Add 1 to the counter and repeat the process for the next 16 bytes.
pub fn ctr_256(key: &[u8; 32], nonce: [u8; 12], data: &mut [u8]) {
    let cipher = Aes256::new(key);

    for (counter, chunk) in (0_u32..).zip(data.chunks_mut(16)) {
        // Create the 16-byte block (Nonce + Counter)
        let mut block = [0u8; 16];
        block[..12].copy_from_slice(&nonce);
        block[12..].copy_from_slice(&counter.to_be_bytes());

        // Encrypt the counter block
        cipher.encrypt_block(&mut block);

        // XOR with data
        for i in 0..chunk.len() {
            chunk[i] ^= block[i];
        }
    }
}

/// Same as the `ctr_256` but the 16-byte chunks are processes in parallel across multiple
/// threads
pub fn parallel_ctr_256(key: &[u8; 32], nonce: [u8; 12], data: &mut [u8]) {
    // Initialize AES
    let cipher = Aes256::new(key);

    // Create a parallel iterator over 16-byte mutable slices
    data.par_chunks_mut(16).enumerate().for_each(|(i, chunk)| {
        let mut block = [0u8; 16];
        block[..12].copy_from_slice(&nonce);

        // Calculate the specific counter the current block using the index
        let block_counter = i as u32;
        block[12..].copy_from_slice(&block_counter.to_be_bytes());

        // Generate the keystream for this specific block
        let mut keystream = block;
        cipher.encrypt_block(&mut keystream);

        // XOR the data with the keystream
        for j in 0..chunk.len() {
            chunk[j] ^= keystream[j];
        }
    });
}
