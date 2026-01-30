# AGENT.md

> Minimal AI guide for bruteforce-wifi development

## Project Overview

**bruteforce-wifi** is a Rust desktop app for WPA/WPA2 password cracking with two engines:
- **Native CPU**: Custom PBKDF2 implementation with Rayon parallelism
- **Hashcat GPU**: 10-100x faster via hashcat integration

## Codebase Structure

```
src/
├── main.rs              # Entry point, panic handler, permission checks
├── app.rs               # Main app state, Message handling
├── lib.rs               # Public API exports
├── theme.rs             # Iced UI theme
├── workers.rs           # Async workers (scan, capture, crack)
├── workers_optimized.rs # Optimized CPU cracking workers
├── core/
│   ├── bruteforce.rs    # Native CPU cracking engine
│   ├── crypto.rs        # PBKDF2, PTK, MIC (WPA crypto)
│   ├── handshake.rs     # PCAP parsing, handshake extraction
│   ├── hashcat.rs       # Hashcat integration (GPU)
│   ├── network.rs       # WiFi scanning, packet capture
│   ├── password_gen.rs  # Zero-allocation password generation
│   └── security.rs      # Security utilities
└── screens/
    ├── crack.rs         # Cracking UI + engine selector
    └── scan_capture.rs  # Scanning & capture UI
```

## Key Implementation Details

### Two Attack Methods

1. **4-Way Handshake** ([`src/core/network.rs`](src/core/network.rs))
   - Captures M1 (ANonce) and M2 (SNonce + MIC) EAPOL frames
   - Requires client device to reconnect to AP
   - Traditional WPA/WPA2 attack method

2. **PMKID** ([`src/core/network.rs`](src/core/network.rs))
   - Extracts PMKID from RSN Information Element in beacon frames
   - **Clientless**: No devices need to be connected
   - Faster and stealthier than handshake capture

Both methods produce a `.pcap` file that can be cracked offline.

### Native CPU Engine ([`src/core/bruteforce.rs`](src/core/bruteforce.rs))

- **Zero-allocation**: PasswordBuffer on stack, no heap allocations
- **Parallelism**: Rayon work-stealing on all cores
- **Performance**: ~30% faster than generic PBKDF2
- **Speed**: ~10K-100K passwords/sec

### Hashcat Integration ([`src/core/hashcat.rs`](src/core/hashcat.rs))

- **Auto-detect devices**: CPU+GPU (3), GPU-only (2), CPU-only (1)
- **Progress parsing**: Speed, Restore.Point, Keyspace from stdout/stderr
- **Fallback**: CPU+GPU → GPU-only if "No devices found/left"
- **Potfile**: Always cleaned before each run to avoid cached results

### Async Workers ([`src/workers.rs`](src/workers.rs))

- **Tokio**: Async task spawning for background operations
- **Channels**: Unbounded channels for progress updates
- **Cancellation**: AtomicBool for graceful stop
- **Progress**: Send every 5000 attempts (balance performance vs UI)

### Message Flow

```
User Action → Message → app.rs::update() → Worker (async) → Progress → UI Update
```

Key messages:
- `StartScan` → `scan_networks_async()` → `ScanComplete`
- `StartCapture` → `capture_async()` → `CaptureProgress`
- `StartCrack` → `crack_hashcat_async()` or `crack_numeric_optimized()` → `CrackProgress`

## Development Workflow

### Before Editing

```bash
# Check for uncommitted changes
git diff

# Read relevant files
cat src/app.rs
cat src/workers.rs
cat src/core/hashcat.rs
```

### Making Changes

1. **Plan**: Identify what needs to change and dependencies
2. **Implement**: Use `edit_file` or `apply_diff` with 3-5 lines context
3. **Format**: Always run `cargo fmt --all`
4. **Lint**: Always run `cargo clippy --all-targets --all-features -- -D warnings`
5. **Build**: Run `cargo build --release`
6. **Test**: Run `cargo test` and manual testing if needed

### After Every Iteration

```bash
# Format code (CI command - must pass)
cargo fmt -- --check

# Run clippy (CI command - must pass with zero warnings)
cargo clippy --all-targets --all-features -- -D warnings

# Build release
cargo build --release

# Run tests
cargo test
```

## Code Conventions

### Rust Style

- **Format**: `rustfmt.toml` (100 chars, Unix newlines)
- **Linting**: `clippy.toml` (cognitive_complexity_threshold=30)
- **Naming**: `snake_case` for functions, `PascalCase` for types
- **Imports**: Grouped by std → external → internal

### Error Handling

- Use `Result<T>` for recoverable errors
- Use `anyhow::Result` for error propagation
- Provide descriptive error messages with context

### Documentation

- Modules: `/*! ... */` at file start
- Public functions: `/// ...` with examples if complex
- Inline comments: `//` for "why", not "what"

## Testing

### Unit Tests

```bash
cargo test --lib
```

### Integration Tests

```bash
cargo test --test '*'
```

### Manual Testing

```bash
# Test hashcat workflow
./test_hashcat.sh /tmp/capture.pcap test123

# Run the app
sudo ./target/release/brutifi
```

## Security Considerations

- ⚠️ Never log passwords in plain text
- ⚠️ Use `/tmp` for temporary files
- ⚠️ Clean sensitive files (.22000, potfile)
- ⚠️ sudo required for network capture (macOS)

## Quick Reference

### Essential Commands

```bash
# CI Commands (exactly as CI runs them)
cargo fmt -- --check                                    # Format check
cargo clippy --all-targets --all-features -- -D warnings # Lint (zero warnings)
cargo build --verbose                                    # Build
cargo test --verbose                                     # Test

# Development Commands
cargo fmt --all                                          # Auto-format code
cargo clippy --all-targets --all-features -- -D warnings # Check for warnings
cargo build --release                                    # Release build

# Run app
sudo ./target/release/brutifi

# Test hashcat
hashcat -m 22000 /tmp/test.22000 -a 3 ?d?d?d?d?d?d?d?d -D 2 --force

# Convert PCAP to hashcat format
hcxpcapngtool -o /tmp/test.22000 /tmp/capture.pcap
```

### File Locations

- **Temporary files**: `/tmp/`
- **Potfile**: `/tmp/brutyfi_hashcat.potfile`
- **Hash files**: `/tmp/*.22000`
- **Capture files**: User-selected (default: `capture.pcap`)

## Philosophy

**Better to ask than to break code.**

When in doubt:
1. Read this guide
2. Check git history: `git log --grep="keyword"`
3. Test locally before committing
4. Ask for clarification if ambiguous
5. Document new solutions

---

**Remember**: After every code change, always run these **exact CI commands**:

```bash
cargo fmt -- --check                                    # Check formatting (CI exact)
cargo clippy --all-targets --all-features -- -D warnings # Check lints (CI exact)
```

If formatting fails, auto-fix with:
```bash
cargo fmt --all
```

These checks are **enforced by CI** and must pass before merging.
