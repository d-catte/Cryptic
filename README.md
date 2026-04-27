# Cryptic
Cryptic is a suite of cryptographical techniques recreated with the modern programming language, Rust. 
These implementations are for educational purposes only and may not be secure (or efficient) enough for practical
implementations. This was done as a research project for my Number Theory and Cryptography class.

## Features
### Algorithms
- Diffie-Hellman Key Exchange
- Extended Euclidean Algorithm
- Fast Exponentiation
- Jacobi Symbol
### Ciphers
- Affine
- Vigenere
### Cryptosystems
- RSA
- Rabin
- Goldwasser-Micali
- AES
- Parallel AES
### Throughput Benchmarks
- Compares the throughput of all cryptosystems at various input sizes
- Exposes limitations of prime-based cryptosystems

## Usage
Run the application in the terminal or console. Use the arrow keys to change a selection and use enter to select.
Inputting long text may result in hangs as cryptosystems that use primality tests may frequently fail. This is due
to the number of primes for large values becoming increasingly rare.

## Research Paper
My research paper about the Quadratic Residuosity Problem and its significance in cryptography can be found [here](https://docs.google.com/document/d/1KcRfHl_ZGa9piB7X0tCy9pdXNk3_LeDIN5uTY6qRJBE/edit?usp=sharing).