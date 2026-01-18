/*!
 * Offline WPA/WPA2 bruteforce engine (Optimized)
 *
 * This module implements high-performance offline password cracking
 * against captured WPA/WPA2 handshakes.
 *
 * Performance optimizations:
 * - Hardware-accelerated PBKDF2 (SHA-NI/AES-NI when available)
 * - Zero-allocation password generation and verification
 * - Parallel password testing with Rayon work-stealing
 * - Lock-free progress tracking with relaxed atomics
 * - Cache-friendly batch processing
 */

use anyhow::Result;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::core::crypto;
use crate::core::handshake::Handshake;
use crate::core::password_gen::{ParallelPasswordGenerator, PasswordBuffer};

/// Offline bruteforce engine for WPA/WPA2 handshakes
pub struct OfflineBruteForcer {
    pub handshake: Handshake,
    pub threads: usize,
    pub attempts: Arc<AtomicU64>,
    pub found: Arc<AtomicBool>,
}

impl OfflineBruteForcer {
    pub fn new(handshake: Handshake, threads: usize) -> Result<Self> {
        // Configure rayon thread pool with optimized settings
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .stack_size(8 * 1024 * 1024) // Increased stack size for better performance
            .build_global()
            .ok();

        Ok(Self {
            handshake,
            threads,
            attempts: Arc::new(AtomicU64::new(0)),
            found: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Zero-allocation password test using raw bytes
    /// This is the hot path optimized for maximum throughput
    #[inline(always)]
    fn test_password_bytes(&self, password: &[u8]) -> bool {
        self.attempts.fetch_add(1, Ordering::Relaxed);

        crypto::verify_password_bytes(
            password,
            self.handshake.ssid.as_bytes(),
            &self.handshake.ap_mac,
            &self.handshake.client_mac,
            &self.handshake.anonce,
            &self.handshake.snonce,
            &self.handshake.eapol_frame,
            &self.handshake.mic,
            self.handshake.key_version,
        )
    }

    /// Test a PasswordBuffer (zero-copy)
    #[inline(always)]
    fn test_password_buffer(&self, buf: &PasswordBuffer) -> bool {
        self.test_password_bytes(buf.as_bytes())
    }

    /// Bruteforce using numeric passwords (zero-allocation optimized)
    pub fn crack_numeric(&self, min_length: usize, max_length: usize) -> Result<Option<String>> {
        let _start_time = Instant::now();
        let found_password: Arc<parking_lot::Mutex<Option<String>>> =
            Arc::new(parking_lot::Mutex::new(None));

        // Process each length
        for length in min_length..=max_length {
            if self.found.load(Ordering::Acquire) {
                break;
            }

            let generator = ParallelPasswordGenerator::new(length, self.threads);
            let ranges: Vec<_> = generator.range_batches().collect();

            // Process ranges in parallel - each thread generates passwords on-the-fly
            // This avoids allocating millions of String objects
            let found_ref = Arc::clone(&self.found);
            let found_password_ref = Arc::clone(&found_password);

            ranges.par_iter().find_any(|(start, end)| {
                // Early exit check
                if found_ref.load(Ordering::Acquire) {
                    return false;
                }

                // Process this range with zero allocations
                for num in *start..*end {
                    // Check periodically for early termination (every 64 passwords)
                    if num & 0x3F == 0 && found_ref.load(Ordering::Acquire) {
                        return false;
                    }

                    let buf = PasswordBuffer::from_numeric(num, length);
                    if self.test_password_buffer(&buf) {
                        // Convert to String only when found
                        let password =
                            unsafe { String::from_utf8_unchecked(buf.as_bytes().to_vec()) };
                        *found_password_ref.lock() = Some(password);
                        found_ref.store(true, Ordering::Release);
                        return true;
                    }
                }
                false
            });

            if self.found.load(Ordering::Acquire) {
                break;
            }
        }

        let result = found_password.lock().clone();
        Ok(result)
    }

    /// Bruteforce using wordlist (optimized)
    pub fn crack_wordlist(&self, passwords: Vec<String>) -> Result<Option<String>> {
        let _start_time = Instant::now();
        let found_password: Arc<parking_lot::Mutex<Option<String>>> =
            Arc::new(parking_lot::Mutex::new(None));

        let found_ref = Arc::clone(&self.found);
        let found_password_ref = Arc::clone(&found_password);

        // Optimal chunk size balances parallelism overhead vs work-stealing efficiency
        let chunk_size = (passwords.len() / (self.threads * 8)).clamp(1000, 100_000);

        passwords.par_chunks(chunk_size).find_any(|chunk| {
            for (i, password) in chunk.iter().enumerate() {
                // Check for early termination every 32 passwords
                if i & 0x1F == 0 && found_ref.load(Ordering::Acquire) {
                    return false;
                }

                // Use bytes directly to avoid redundant string operations
                if self.test_password_bytes(password.as_bytes()) {
                    *found_password_ref.lock() = Some(password.clone());
                    found_ref.store(true, Ordering::Release);
                    return true;
                }
            }
            false
        });

        let result = found_password.lock().clone();
        Ok(result)
    }

    /// Get current attempt count
    pub fn attempts(&self) -> u64 {
        self.attempts.load(Ordering::Relaxed)
    }
}
