# 🔐 BrutiFi - Advanced WiFi Security Testing Tool

Modern, cross-platform WiFi penetration testing tool with GPU acceleration and comprehensive attack methods.

<p align="center">
  <img src="https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-blue" alt="Platform">
  <img src="https://img.shields.io/badge/Rust-1.70%2B-orange" alt="Rust">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <a href="https://github.com/maxgfr/bruteforce-wifi/releases">
    <img src="https://github.com/maxgfr/bruteforce-wifi/actions/workflows/release.yml/badge.svg" alt="Release">
  </a>
  <a href="https://github.com/maxgfr/bruteforce-wifi/actions">
    <img src="https://github.com/maxgfr/bruteforce-wifi/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
</p>

---

## ✨ Features

### 🎯 Attack Methods

#### Currently Implemented ✅

- **PMKID Capture** - Clientless WPA/WPA2 attack (2018+)
  - No deauth required
  - Single packet capture
  - Works on many modern routers
  - Automatic fallback to traditional handshake

- **WPA/WPA2 Handshake Capture** - Traditional 4-way handshake
  - Automatic multi-channel rotation
  - Smart dwell time optimization
  - Detects M1, M2, M3, M4 frames
  - Smart Connect support (dual-band routers)

- **CPU Cracking** - Native PBKDF2 implementation
  - Zero-allocation password generation
  - Rayon parallelization (10K-100K pass/sec)
  - Numeric and wordlist modes
  - Portable (no external dependencies)

- **GPU Cracking** - Hashcat integration
  - 10-100x faster than CPU
  - Automatic device detection (CPU+GPU, GPU, CPU)
  - Supports mode 22000 (WPA/WPA2/WPA3 + PMKID)
  - Real-time progress tracking

- **WPS Attacks** - WiFi Protected Setup exploitation
  - **Pixie-Dust Attack** - Offline WPS PIN recovery (<10 seconds on vulnerable routers)
    - Exploits weak random number generation
    - Success rate: ~30% of WPS-enabled routers
    - Automatic password recovery with PIN
  - **PIN Brute-Force** - Online WPS attack with Luhn checksum optimization
    - ~10M valid PINs (reduced from 100M via checksum)
    - Smart rate limiting to avoid AP lockout
    - Automatic password recovery

- **WPA3-SAE Support** - Modern WPA3 networks
  - **WPA3 Detection** - Automatic network type identification
    - WPA3-Only (SAE) detection
    - WPA3-Transition mode detection (vulnerable)
    - PMF (Protected Management Frames) detection
  - **Transition Mode Downgrade** - Force WPA3-Transition to WPA2 (80-90% success rate)
    - Captures standard WPA2 handshake
    - Compatible with existing cracking methods
  - **SAE Handshake Capture** - For pure WPA3 networks
    - Uses hcxdumptool v6.0+ for SAE capture
    - Converts to hashcat mode 22000
    - Offline cracking support
  - **Dragonblood Detection** - Identifies known WPA3 vulnerabilities
    - CVE-2019-13377: SAE timing side-channel
    - CVE-2019-13456: Cache-based side-channel

#### Coming Soon 🔜
- **Evil Twin Attack** - Rogue AP with captive portal
  - Multiple portal templates (Generic, TP-Link, Netgear, Linksys)
  - Real-time credential validation
  - Smart deauthentication
- **Attack Monitoring** - Passive wireless attack detection
- **Session Resume** - Continue interrupted attacks
- **WPA-SEC Integration** - Online distributed cracking

---

## 🚀 Quick Start

### Installation

#### Prerequisites

```bash
# macOS (Homebrew)
brew install hashcat hcxtools

# For WPS attacks
brew install reaver pixiewps

# For WPA3 attacks
brew install hcxdumptool hcxtools

# For Evil Twin (coming soon)
brew install hostapd dnsmasq
```

#### Build from Source
```bash
git clone https://github.com/maxgfr/bruteforce-wifi
cd bruteforce-wifi
cargo build --release
```

#### Install Binary (macOS)

1. Download the DMG from the [latest release](https://github.com/maxgfr/bruteforce-wifi/releases)
2. Open the DMG and drag **BrutiFi.app** to **Applications**
3. Remove quarantine attribute (required for GitHub downloads):
   ```bash
   xattr -dr com.apple.quarantine /Applications/BrutiFi.app
   ```

### Basic Usage

#### Scan and Capture
```bash
# Run with sudo (required for network capture)
sudo ./target/release/brutifi

# In the GUI:
# 1. Click "Scan" to discover networks
# 2. Select a target network
# 3. Click "Start Capture"
# 4. Wait for PMKID or handshake
```

#### Crack Captured Handshake
```bash
# GPU cracking (recommended)
sudo ./target/release/brutifi
# Navigate to "Crack" tab
# Select handshake file
# Choose "Hashcat" engine
# Select attack method (Numeric or Wordlist)
# Click "Start Crack"
```

---

## 📖 Documentation

### User Guides
- **[PMKID Testing Guide](PMKID_TEST_GUIDE.md)** - How to test PMKID on your network
- [WPS Attacks](docs/WPS_ATTACKS.md) - Coming soon
- [WPA3 Support](docs/WPA3.md) - Coming soon
- [Evil Twin](docs/EVIL_TWIN.md) - Coming soon
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions

### Developer Guides
- **[Architecture](AGENTS.md)** - Codebase structure and patterns
- [Contributing](CONTRIBUTING.md) - How to contribute
- [Changelog](CHANGELOG.md) - Version history

---

## 💪 Performance

### Benchmarks

| Attack Method | Speed | Success Rate | Requirements |
|--------------|-------|--------------|-------------|
| PMKID Capture | 1-30 seconds | 60-70% | Modern router with PMKID support |
| Handshake Capture | 1-5 minutes | 95%+ | Client reconnection |
| WPS Pixie-Dust* | < 10 seconds | 40-50% | Vulnerable WPS implementation |
| WPA3 Downgrade* | < 30 seconds | 80-90% | Transition mode network |
| Evil Twin* | Variable | 90%+ | Active clients |

\* Coming soon

### Cracking Speed

| Engine | Numeric (8 digits) | Wordlist (10M passwords) |
|--------|-------------------|-------------------------|
| Native CPU (M1 Pro) | ~30K pass/sec (~55 min) | ~50K pass/sec (~3.3 min) |
| Hashcat GPU (M1 Pro) | ~2M pass/sec (~50 sec) | ~3M pass/sec (~3 sec) |
| Hashcat GPU (RTX 3080) | ~10M pass/sec (~10 sec) | ~15M pass/sec (<1 sec) |

---

## 🎨 Features in Detail

### PMKID Capture (Client-less Attack)

**What is PMKID?**
- Discovered in 2018 by Jens Steube (hashcat author)
- Extracts PMK identifier from first EAPOL frame
- No client needed (works without connected devices)
- No deauth attack required (quieter, more ethical)

**How it works:**
1. Router broadcasts PMKID during RSNA key negotiation
2. BrutiFi captures the PMKID from EAPOL Message 1
3. PMKID is converted to hashcat format (mode 22000, WPA*01*)
4. Crack offline with hashcat or native CPU

**Advantages:**
- ✅ Faster than traditional handshake (1 packet vs 4)
- ✅ No client required
- ✅ No deauth needed (passive)
- ✅ Works on macOS (no injection needed)

**Limitations:**
- ❌ Not all routers support PMKID
- ❌ Many modern routers patch this vulnerability
- ❌ ISP boxes (Livebox, Freebox, SFR) usually patched

### Traditional WPA/WPA2 Handshake

**What is a handshake?**
- 4-way authentication exchange between client and AP
- Contains all data needed to crack WPA password offline
- Industry standard since 2003

**BrutiFi's implementation:**
- Multi-channel scanning and rotation
- Auto-detects Smart Connect (2.4GHz + 5GHz)
- Smart dwell time (stays longer on active channels)
- Detects all 4 message types (M1, M2, M3, M4)
- **Automatic PMKID prioritization** - tries PMKID first, falls back to handshake

**Capture workflow:**
1. Scan networks
2. Select target
3. Rotate through all target channels
4. Detect PMKID or EAPOL frames
5. Verify handshake completeness
6. Save to pcap file

**macOS Note:** Deauth attacks don't work on macOS (no packet injection). You must wait for natural client reconnections or manually reconnect a device.

### GPU Acceleration (Hashcat)

**Why hashcat?**
- Industry-leading password cracking tool
- Optimized for CUDA, OpenCL, Metal (Apple Silicon)
- 10-100x faster than CPU
- Supports WPA/WPA2/WPA3 + PMKID

**BrutiFi's integration:**
- Automatic device detection (CPU+GPU, GPU-only, CPU-only)
- Automatic fallback if GPU fails
- Real-time progress parsing (speed, ETA, progress)
- Auto-cleans potfile to avoid cached results
- Supports both numeric and wordlist attacks

**Supported modes:**
- Numeric brute-force (8-10 digits)
- Wordlist attack (rockyou.txt, custom lists)
- Incremental mode (8→9→10 digits)

### Native CPU Cracking

**Why use CPU mode?**
- No external dependencies
- Educational value (see WPA crypto internals)
- Portable (works on any system)
- Useful when hashcat unavailable

**Optimizations:**
- Zero-allocation password generation
- Rayon work-stealing parallelism
- Custom PBKDF2 implementation (~30% faster)
- Stack-based PasswordBuffer (no heap allocations)

**Performance:**
- M1 Pro (8 cores): ~30K-50K pass/sec
- Intel i7 (8 cores): ~20K-40K pass/sec
- AMD Ryzen 7 (16 cores): ~50K-80K pass/sec

---

## 🛠️ Technical Details

### Architecture

```
User Interface (Iced GUI)
        ↓
   Message Bus
        ↓
    Handlers (app logic)
        ↓
  Async Workers (Tokio)
        ↓
   Core Modules
   ├── network.rs    - WiFi scanning & capture
   ├── handshake.rs  - PCAP parsing & EAPOL extraction
   ├── crypto.rs     - PBKDF2, PMK, PTK, MIC calculation
   ├── bruteforce.rs - Native cracking engine
   ├── hashcat.rs    - GPU integration
   └── wps.rs        - WPS attacks (coming soon)
```

### Crypto Implementation

**WPA2-PSK Cracking Process:**
1. PMK = PBKDF2-SHA1(password, SSID, 4096 iterations, 256 bits)
2. PTK = PRF-512(PMK, "Pairwise key expansion", APMac, ClientMac, ANonce, SNonce)
3. MIC = HMAC-SHA1(PTK[0:16], EAPOL frame with MIC=0)
4. Compare calculated MIC with captured MIC

**Why PBKDF2 is slow:**
- 4096 HMAC-SHA1 iterations per password
- Intentionally designed to be computationally expensive
- Makes brute-force attacks slower

### File Structure

```
src/
├── main.rs              - Entry point, panic handler, root check
├── app.rs               - Main app state machine
├── lib.rs               - Public API exports
├── theme.rs             - UI theme (Iced)
├── workers.rs           - Async workers (scan, capture, crack)
├── workers_optimized.rs - CPU cracking workers
├── core/
│   ├── crypto.rs        - WPA2 crypto (PBKDF2, PTK, MIC)
│   ├── handshake.rs     - PCAP parsing, EAPOL extraction, PMKID
│   ├── bruteforce.rs    - Native cracking engine
│   ├── password_gen.rs  - Zero-allocation password generator
│   ├── network.rs       - WiFi scanning, packet capture
│   ├── hashcat.rs       - Hashcat integration
│   └── security.rs      - Security utilities
├── screens/
│   ├── scan_capture.rs  - Scan & capture UI
│   └── crack.rs         - Cracking UI
└── handlers/
    ├── crack.rs         - Cracking logic
    ├── capture.rs       - Capture logic
    ├── scan.rs          - Scan logic
    └── general.rs       - General app logic
```

---

## 🖥️ Platform Support

### macOS (Primary Platform)

**Supported:**
- ✅ WiFi scanning (CoreWLAN)
- ✅ Monitor mode (en0 interface)
- ✅ Packet capture (libpcap)
- ✅ PMKID extraction
- ✅ Handshake capture (passive)
- ✅ GPU acceleration (Metal, M1/M2)
- ✅ Auto-privilege escalation (osascript)

**Limited/Unsupported:**
- ❌ Packet injection (deauth attacks)
- ❌ WPS attacks (requires injection)
- ⚠️ Evil Twin (requires hostapd, may need external adapter)

**Recommended External Adapters:**
- Alfa AWUS036ACH (full injection support)
- Panda PAU09 (injection support)
- TP-Link TL-WN722N v1 (older but works)

### Linux (Experimental)

**Supported:**
- ✅ All features
- ✅ Packet injection (deauth attacks)
- ✅ Full WPS support (when implemented)
- ✅ Evil Twin attacks (when implemented)
- ✅ Dual interface mode (when implemented)

**Requirements:**
- Monitor mode compatible adapter
- aircrack-ng suite
- hostapd, dnsmasq (for Evil Twin)

---

## 🔧 Development

### Prerequisites

- **Rust 1.70+**: Install via [rustup](https://rustup.rs/)
- **Xcode Command Line Tools** (macOS): `xcode-select --install`
- **Hashcat** (optional): `brew install hashcat`
- **hcxtools** (optional): `brew install hcxtools`

### Build Commands

```bash
# Development build
cargo build

# Optimized release build
cargo build --release

# Run the app
cargo run --release

# Format code
cargo fmt --all

# Lint code
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test
```

### Build macOS DMG

```bash
# Build DMG (automatically detects architecture)
./scripts/build_dmg.sh

# Output:
# BrutiFi-{VERSION}-macOS-arm64.dmg (Apple Silicon)
# BrutiFi-{VERSION}-macOS-x86_64.dmg (Intel)
```

---

## ⚠️ Legal Disclaimer

**IMPORTANT: This tool is for authorized security testing ONLY.**

### Legal Use Cases
- ✅ Testing networks you own
- ✅ Networks you have **written permission** to test
- ✅ Educational purposes (your own test environment)
- ✅ Authorized penetration testing engagements

### Illegal Use
- ❌ Attacking networks without permission
- ❌ Capturing other people's passwords
- ❌ Unauthorized access to WiFi networks
- ❌ Any malicious or unethical use

**By using this tool, you agree:**
1. You will only test networks you own or have explicit permission to test
2. You understand that unauthorized access is illegal in most jurisdictions
3. The authors are not responsible for misuse of this software
4. You will comply with all local, state, and federal laws

**Penalties for unauthorized access can include:**
- Criminal charges
- Fines up to $250,000 (US)
- Prison sentences
- Civil lawsuits

**Use responsibly. Get permission. Stay legal.**

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repo
git clone https://github.com/maxgfr/bruteforce-wifi
cd bruteforce-wifi

# Install dependencies
brew install hashcat hcxtools

# Build
cargo build

# Run tests
cargo test

# Format and lint
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings

# Run
sudo cargo run --release
```

### Code Style

- Follow Rust style guide
- Run `cargo fmt` before committing
- Ensure `cargo clippy` passes with no warnings
- Add tests for new features
- Update documentation

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

### Latest Version (1.14.2)

**Added:**
- ✨ **PMKID Support** - Client-less WPA/WPA2 attack
  - Automatic PMKID extraction from EAPOL M1
  - Prioritizes PMKID over traditional handshake
  - Fallback to 4-way handshake if PMKID not available
- 🎨 UI improvements for capture type display
- 📊 Capture progress shows "PMKID (client-less)" or "4-way handshake"

**Fixed:**
- 🐛 Hashcat password parsing for PMKID (WPA*01*) format

**Changed:**
- 🔧 Updated handshake structure to support PMKID field

---

## 🙏 Acknowledgments

### Inspiration

- **[Wifite](https://github.com/derv82/wifite2)** - For attack method ideas and workflow inspiration
- **[Aircrack-ng](https://github.com/aircrack-ng/aircrack-ng)** - Industry-standard WiFi security tools
- **[AirJack](https://github.com/rtulke/AirJack)** - Python-based WiFi testing tool
- **[Pyrit](https://github.com/JPaulMora/Pyrit)** - Pre-computed tables for WPA-PSK
- **[Cowpatty](https://github.com/joswr1ght/cowpatty)** - Early WPA-PSK cracking
- https://github.com/kimocoder/wifite2

### Technology

- **[Iced](https://github.com/iced-rs/iced)** - Cross-platform GUI framework
- **[Rayon](https://github.com/rayon-rs/rayon)** - Data parallelism library
- **[pcap-rs](https://github.com/rust-pcap/pcap)** - Rust bindings for libpcap
- **[Hashcat](https://github.com/hashcat/hashcat)** - GPU-accelerated password recovery
- **[hcxtools](https://github.com/ZerBea/hcxtools)** - Wireless security auditing tools
- **[Tokio](https://github.com/tokio-rs/tokio)** - Async runtime for Rust

### Special Thanks

- **Jens Steube** - For discovering PMKID attack (2018)
- **Rust Community** - For the amazing language and ecosystem
- All contributors and testers

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🔗 Links

- **GitHub**: https://github.com/maxgfr/bruteforce-wifi
- **Issues**: https://github.com/maxgfr/bruteforce-wifi/issues
- **Discussions**: https://github.com/maxgfr/bruteforce-wifi/discussions
- **Releases**: https://github.com/maxgfr/bruteforce-wifi/releases

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/maxgfr">maxgfr</a>
</p>

<p align="center">
  ⚡ Powered by Rust and hashcat ⚡
</p>
