use crate::Cryptosystems;
use crate::basic::algorithms;
use num_bigint::BigUint;
use rand::RngCore;
use std::fs::File;
use std::io::Write;
use std::time::{Duration, Instant};

const BYTE_TEST_SIZES: [usize; 10] = [
    1,          // 1 bye
    10,         // 10 bytes
    100,        // 100 bytes
    1000,       // 1kb
    10000,      // 10kb
    100000,     // 100kb
    1000000,    // 1mb
    10000000,   // 10mb
    100000000,  // 100mb
    1000000000, // 1Gb
];

const TRIALS: u8 = 10;

const MAX_TRIAL_DURATION: Duration = Duration::from_secs(120);

pub fn start_benchmark(selected_cryptosystems: &[Cryptosystems]) {
    // Store rows for the CSV as (Algorithm, Size, AvgTimeSecs, ThroughputMBs)
    let mut csv_rows = Vec::new();

    for cryptosystem in selected_cryptosystems {
        if let Cryptosystems::Back = cryptosystem {
            continue;
        }

        let algo_name = format!("{:?}", cryptosystem);
        println!("Benchmarking {}...", algo_name);

        for &size in &BYTE_TEST_SIZES {
            // Heuristic check to prevent starting a fail-loop
            // Asymmetric cryptosystems are too slow for large data.
            if is_asymmetric(cryptosystem) && size > 1_000_000 {
                println!(
                    "  Size {} bytes: Skipping (Asymmetric limit exceeded)",
                    size
                );
                continue;
            }

            let mut total_duration = Duration::ZERO;
            let mut trials_completed = 0;
            let mut timed_out = false;

            for _ in 0..TRIALS {
                let mut input = vec![0u8; size];
                rand::thread_rng().fill_bytes(&mut input);

                let start = Instant::now();

                // Run the specific algorithm
                run_algo(cryptosystem, &input);

                let elapsed = start.elapsed();

                // Timeout Check
                if elapsed > MAX_TRIAL_DURATION {
                    println!(
                        "  Size {} bytes: Timed out (> 5 mins). Skipping remaining trials.",
                        size
                    );
                    timed_out = true;
                    break;
                }

                total_duration += elapsed;
                trials_completed += 1;
            }

            // Record data if at least one trial finished without timing out
            if trials_completed > 0 && !timed_out {
                let avg_duration = total_duration / trials_completed;
                let secs = avg_duration.as_secs_f64();
                let mb_per_sec = (size as f64 / 1_000_000.0) / secs;

                println!(
                    "  Size {:>10} bytes | Avg: {:.4}s | {:.2} MB/s",
                    size, secs, mb_per_sec
                );

                csv_rows.push(format!("{},{},{},{}", algo_name, size, secs, mb_per_sec));
            }
        }
    }

    // Export to CSV
    export_to_csv(csv_rows);
    println!("Benchmarks completed successfully!");
}

fn is_asymmetric(c: &Cryptosystems) -> bool {
    matches!(
        c,
        Cryptosystems::RSA | Cryptosystems::Rabin | Cryptosystems::Goldwasser
    )
}

fn run_algo(c: &Cryptosystems, input: &[u8]) {
    match c {
        Cryptosystems::RSA => {
            let m = BigUint::from_bytes_le(input);
            let encrypt = algorithms::rsa_encrypt(&m, false);
            let _ = algorithms::rsa_decrypt(&encrypt.0, &encrypt.1, &encrypt.2);
        }
        Cryptosystems::Rabin => {
            let _ = algorithms::rabin(input);
        }
        Cryptosystems::Goldwasser => {
            let _ = algorithms::goldwasser_micali(input);
        }
        Cryptosystems::AES => {
            let _ = algorithms::aes(input);
        }
        Cryptosystems::AESPARALLEL => {
            let _ = algorithms::aes_parallel(input);
        }
        _ => {}
    }
}

fn export_to_csv(rows: Vec<String>) {
    let mut file = File::create("benchmark_results.csv").expect("Unable to create file");
    writeln!(file, "Algorithm,ByteSize,AverageTimeSeconds,ThroughputMBps").unwrap();
    for row in rows {
        writeln!(file, "{}", row).unwrap();
    }
    println!("\nResults exported to benchmark_results.csv");
}
