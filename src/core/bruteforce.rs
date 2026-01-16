/*!
 * Offline WPA/WPA2 bruteforce engine
 *
 * This module implements high-performance offline password cracking
 * against captured WPA/WPA2 handshakes.
 *
 * Performance optimizations:
 * - Parallel password testing with Rayon
 * - Efficient batch processing
 * - Lock-free progress tracking
 * - Minimal allocations
 */

use anyhow::Result;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::core::crypto;
use crate::core::handshake::Handshake;
use crate::core::password_gen::ParallelPasswordGenerator;

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

    /// Test a single password against the handshake
    #[inline(always)]
    fn test_password(&self, password: &str) -> bool {
        self.attempts.fetch_add(1, Ordering::Relaxed);

        crypto::verify_password(
            password,
            &self.handshake.ssid,
            &self.handshake.ap_mac,
            &self.handshake.client_mac,
            &self.handshake.anonce,
            &self.handshake.snonce,
            &self.handshake.eapol_frame,
            &self.handshake.mic,
            self.handshake.key_version,
        )
    }

    /// Bruteforce using numeric passwords
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

            // Process batches in parallel
            for batch in generator.batches() {
                if self.found.load(Ordering::Acquire) {
                    break;
                }

                let found_ref = Arc::clone(&self.found);
                let found_password_ref = Arc::clone(&found_password);

                // Parallel password testing with Acquire ordering for immediate stop
                let result = batch.par_iter().find_any(|password| {
                    if found_ref.load(Ordering::Acquire) {
                        return false;
                    }

                    if self.test_password(password) {
                        // Store password BEFORE setting flag
                        *found_password_ref.lock() = Some(password.to_string());
                        found_ref.store(true, Ordering::Release);
                        true
                    } else {
                        false
                    }
                });

                if result.is_some() {
                    break;
                }
            }

            if self.found.load(Ordering::Acquire) {
                break;
            }
        }

        let result = found_password.lock().clone();
        Ok(result)
    }

    /// Bruteforce using wordlist
    pub fn crack_wordlist(&self, passwords: Vec<String>) -> Result<Option<String>> {
        let _start_time = Instant::now();
        let found_password: Arc<parking_lot::Mutex<Option<String>>> =
            Arc::new(parking_lot::Mutex::new(None));

        let found_ref = Arc::clone(&self.found);
        let found_password_ref = Arc::clone(&found_password);

        // Parallel processing with optimal chunk size
        // Larger chunks reduce overhead and improve cache locality
        let chunk_size = (passwords.len() / (self.threads * 4)).clamp(500, 50000);

        passwords.par_chunks(chunk_size).find_any(|chunk| {
            for password in chunk.iter() {
                if found_ref.load(Ordering::Acquire) {
                    return false;
                }

                if self.test_password(password) {
                    // Store password BEFORE setting flag
                    *found_password_ref.lock() = Some(password.to_string());
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
