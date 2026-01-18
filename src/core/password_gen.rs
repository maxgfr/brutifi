/*!
 * Numeric password generation for WPA/WPA2 bruteforce
 *
 * Optimized for parallel processing with ZERO heap allocations in the hot path.
 * Uses stack-allocated byte buffers for maximum throughput.
 */

/// Maximum password length we support (WPA allows 8-63 characters)
pub const MAX_PASSWORD_LEN: usize = 16;

/// Stack-allocated password buffer to avoid heap allocations
#[derive(Clone, Copy)]
pub struct PasswordBuffer {
    data: [u8; MAX_PASSWORD_LEN],
    len: u8,
}

impl PasswordBuffer {
    /// Create a new password buffer from a numeric value
    #[inline(always)]
    pub fn from_numeric(mut num: u64, length: usize) -> Self {
        debug_assert!(length <= MAX_PASSWORD_LEN);
        let mut data = [b'0'; MAX_PASSWORD_LEN];
        let mut pos = length;

        // Build number from right to left
        while pos > 0 {
            pos -= 1;
            data[pos] = (num % 10) as u8 + b'0';
            num /= 10;
        }

        Self {
            data,
            len: length as u8,
        }
    }

    /// Get the password as a byte slice (zero-copy)
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

/// Numeric range for parallel iteration
#[derive(Clone, Copy)]
pub struct NumericRange {
    pub start: u64,
    pub end: u64,
    pub length: usize,
}

impl NumericRange {
    #[inline(always)]
    pub fn new(length: usize) -> Self {
        Self {
            start: 0,
            end: 10u64.pow(length as u32),
            length,
        }
    }

    #[inline(always)]
    pub fn total(&self) -> u64 {
        self.end - self.start
    }
}

/// Iterator over numeric passwords as byte buffers (zero allocation)
pub struct NumericPasswordIter {
    current: u64,
    end: u64,
    length: usize,
}

impl NumericPasswordIter {
    #[inline(always)]
    pub fn new(start: u64, end: u64, length: usize) -> Self {
        Self {
            current: start,
            end,
            length,
        }
    }
}

impl Iterator for NumericPasswordIter {
    type Item = PasswordBuffer;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.end {
            return None;
        }
        let buf = PasswordBuffer::from_numeric(self.current, self.length);
        self.current += 1;
        Some(buf)
    }

    #[inline(always)]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.end - self.current) as usize;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for NumericPasswordIter {}

/// Parallel numeric password generator for efficient bruteforce
///
/// Generates numeric passwords in parallel batches with optimal
/// chunk sizing for multi-core processors.
pub struct ParallelPasswordGenerator {
    start: u64,
    end: u64,
    length: usize,
    batch_size: usize,
}

impl ParallelPasswordGenerator {
    /// Create a new parallel generator for a specific length
    pub fn new(length: usize, threads: usize) -> Self {
        let start = 0;
        let end = 10u64.pow(length as u32);

        // Optimal batch size for parallel processing
        // Larger batches reduce rayon overhead, but we need enough batches for work stealing
        let total = end - start;
        let batch_size = ((total as usize) / (threads * 8))
            .clamp(10_000, 500_000);

        Self {
            start,
            end,
            length,
            batch_size,
        }
    }

    #[inline]
    pub fn total_combinations(&self) -> u64 {
        self.end - self.start
    }

    /// Generate batches of (start, end) ranges for parallel processing
    /// Each batch can be processed independently with zero allocations
    #[inline]
    pub fn range_batches(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        (self.start..self.end)
            .step_by(self.batch_size)
            .map(move |batch_start| {
                let batch_end = (batch_start + self.batch_size as u64).min(self.end);
                (batch_start, batch_end)
            })
    }

    /// Get the password length
    #[inline]
    pub fn length(&self) -> usize {
        self.length
    }

    /// Legacy: Generate passwords in batches as Vec<String>
    /// Prefer using range_batches() with NumericPasswordIter for zero-allocation
    #[inline]
    pub fn batches(&self) -> impl Iterator<Item = Vec<String>> + '_ {
        (self.start..self.end)
            .step_by(self.batch_size)
            .map(move |batch_start| {
                let batch_end = (batch_start + self.batch_size as u64).min(self.end);
                let batch_capacity = (batch_end - batch_start) as usize;
                let mut batch = Vec::with_capacity(batch_capacity);

                for num in batch_start..batch_end {
                    batch.push(format_numeric_password(num, self.length));
                }

                batch
            })
    }
}

/// Format a number as a zero-padded password string
#[inline(always)]
pub fn format_numeric_password(num: u64, length: usize) -> String {
    let buf = PasswordBuffer::from_numeric(num, length);
    // SAFETY: PasswordBuffer only contains ASCII digits
    unsafe { String::from_utf8_unchecked(buf.as_bytes().to_vec()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_buffer() {
        let buf = PasswordBuffer::from_numeric(123, 8);
        assert_eq!(buf.as_bytes(), b"00000123");

        let buf = PasswordBuffer::from_numeric(0, 8);
        assert_eq!(buf.as_bytes(), b"00000000");

        let buf = PasswordBuffer::from_numeric(99999999, 8);
        assert_eq!(buf.as_bytes(), b"99999999");
    }

    #[test]
    fn test_numeric_iter() {
        let iter = NumericPasswordIter::new(0, 5, 2);
        let passwords: Vec<_> = iter.map(|b| b.as_bytes().to_vec()).collect();
        assert_eq!(passwords.len(), 5);
        assert_eq!(&passwords[0], b"00");
        assert_eq!(&passwords[4], b"04");
    }

    #[test]
    fn test_generator_basic() {
        let gen = ParallelPasswordGenerator::new(2, 4);
        assert_eq!(gen.total_combinations(), 100);
        assert_eq!(gen.length, 2);
    }

    #[test]
    fn test_generator_range_batches() {
        let gen = ParallelPasswordGenerator::new(4, 4);
        let ranges: Vec<_> = gen.range_batches().collect();
        assert!(!ranges.is_empty());
        assert_eq!(ranges[0].0, 0);
    }

    #[test]
    fn test_generator_format() {
        let gen = ParallelPasswordGenerator::new(3, 4);
        let first_batch = gen.batches().next().unwrap();
        assert_eq!(first_batch[0], "000");
        assert_eq!(first_batch[1], "001");
        assert_eq!(first_batch[2], "002");
    }
}
