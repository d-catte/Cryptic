use crate::basic::algorithms;
use crate::Cryptosystems;
use num_bigint::BigUint;
use rand::RngCore;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task;
use tokio::time::timeout;

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

const MAX_TRIAL_DURATION: Duration = Duration::from_secs(240);

pub async fn start_benchmark(selected_cryptosystems: &[Cryptosystems]) {
    let mut csv_rows = Vec::new();

    for cryptosystem in selected_cryptosystems {
        if matches!(cryptosystem, Cryptosystems::Back) { continue; }

        let algo_name = format!("{:?}", cryptosystem);
        println!("Benchmarking {}...", algo_name);

        'outer: for &size in &BYTE_TEST_SIZES {
            let mut total_duration = Duration::ZERO;
            let mut trials_completed = 0;

            let mut input = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut input);
            let input = Arc::new(input);

            for _ in 0..TRIALS {
                let cryptosystem_clone = cryptosystem.clone();
                let input_ref = Arc::clone(&input);

                let start = Instant::now();

                let handle = task::spawn_blocking(move || {
                    run_algo(&cryptosystem_clone, &input_ref);
                });

                match timeout(MAX_TRIAL_DURATION, handle).await {
                    Ok(Ok(_)) => {
                        total_duration += start.elapsed();
                        trials_completed += 1;
                    }
                    Ok(Err(e)) => {
                        eprintln!("Task panicked: {:?}", e);
                        break 'outer;
                    }
                    Err(_) => {
                        println!("  Size {} bytes: Timed out (> 4 mins). Skipping algorithm.", size);
                        break 'outer;
                    }
                }
            }

            if trials_completed > 0 {
                let avg_duration = total_duration / trials_completed;
                let secs = avg_duration.as_secs_f64();
                let kb_per_sec = (size as f64 / 1_000.0) / secs;

                println!("  Size {:>10} bytes | Avg: {:.4}s | {:.2} KB/s", size, secs, kb_per_sec);
                csv_rows.push(format!("{},{},{},{}", algo_name, size, secs, kb_per_sec));
            }
        }
    }
    export_to_csv(csv_rows);
}

fn run_algo(c: &Cryptosystems, input: &[u8]) {
    match c {
        Cryptosystems::RSA => {
            let m = BigUint::from_bytes_le(input);
            let encrypt = algorithms::rsa_encrypt(&m, false);
            let _ = algorithms::rsa_decrypt(&encrypt.0, &encrypt.1, &encrypt.2);
        }
        Cryptosystems::Rabin => {
            let _ = algorithms::rabin(input, false);
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
