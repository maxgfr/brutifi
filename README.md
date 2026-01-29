# BrutiFi 🔐

> Modern desktop application for WiFi security testing (WPA/WPA2/WPA3/WPS) on macOS with real-time feedback

[![Release](https://github.com/maxgfr/bruteforce-wifi/actions/workflows/release.yml/badge.svg)](https://github.com/maxgfr/bruteforce-wifi/releases)
[![CI](https://github.com/maxgfr/bruteforce-wifi/actions/workflows/ci.yml/badge.svg)](https://github.com/maxgfr/bruteforce-wifi/actions)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**⚠️ EDUCATIONAL USE ONLY - UNAUTHORIZED ACCESS IS ILLEGAL ⚠️**

A high-performance macOS desktop GUI application for testing WiFi password security through multiple attack vectors (WPA/WPA2 handshake, PMKID, WPA3-SAE, WPS, Evil Twin). Built with Rust and Iced, featuring dual cracking engines (Native CPU and Hashcat GPU) for maximum performance.

## ✨ Features

### Core Capabilities

- 🖥️ **Modern Desktop GUI** - Built with Iced framework for smooth, native experience
- 🚀 **Dual Cracking Engines**:
  - **Native CPU**: Custom PBKDF2 implementation with Rayon parallelism (~10K-100K passwords/sec)
  - **Hashcat GPU**: 10-100x faster acceleration with automatic device detection
- 📡 **WiFi Network Scanning** - Real-time discovery with channel detection
- 🎯 **Multi-Protocol Support** - WPA/WPA2, WPA3-SAE, PMKID, WPS attacks
- 🔑 **Dual Attack Modes**:
  - 🔢 Numeric bruteforce (PIN codes: 8-12 digits)
  - 📋 Wordlist attacks (rockyou.txt, custom lists)
- 📊 **Live Progress** - Real-time speed metrics, attempt counters, and ETA
- 🔒 **100% Offline** - No data transmitted anywhere

### Attack Methods

| Method | Target | Description |
|--------|--------|-------------|
| **WPA/WPA2 Handshake** | EAPOL frames | Traditional 4-way handshake capture between client and AP, cracked offline |
| **PMKID** | RSN IE | Clientless attack capturing PMKID from AP beacon frames (no clients needed) |
| **Passive PMKID** | RSN IE | Continuous background sniffing that automatically captures PMKID from roaming clients |
| **WPA3-SAE** | Dragonfly handshake | Modern WPA3 handshake capture with SAE (Simultaneous Authentication of Equals) |
| **WPA3 Downgrade** | Transition mode | Forces WPA2 compatibility on WPA3/WPA2 mixed networks to enable standard attacks |
| **WPS Pixie-Dust** | WPS PIN | Offline attack exploiting weak RNG in WPS implementations to recover PIN |
| **WPS PIN Brute-force** | WPS protocol | Online attack testing PIN combinations directly against the AP's WPS daemon |
| **Evil Twin** | Users | Rogue AP with captive portal capturing credentials from users connecting to fake network |

### Platform Support
- 🍎 **macOS Native** - Apple Silicon and Intel support

## 📦 Installation

### macOS

#### Quick Installation

1. Download the DMG from the latest release (Apple Silicon or Intel).
2. Open the DMG and drag **BrutiFi.app** to **Applications**.
3. Launch the app — macOS will ask for the admin (root) password at startup to enable capture.

#### Remove Quarantine Attribute (Required for GitHub downloads)

When downloading from GitHub, macOS adds a quarantine attribute. You must remove it to launch the app:

```bash
xattr -dr com.apple.quarantine /Applications/BrutiFi.app
```

> This removes security warnings, but WiFi capture in monitor mode still requires root privileges on macOS.

### From Source

```bash
git clone https://github.com/maxgfr/bruteforce-wifi.git
cd bruteforce-wifi
cargo build --release
./target/release/bruteforce-wifi
```

## 🚀 Usage

### Complete Workflow

#### Standard Handshake Attack
```text
1. Scan Networks → 2. Select Target → 3. Capture Handshake → 4. Crack Password
```

#### PMKID Attack (Clientless)
```text
1. Scan Networks → 2. Select Target → 3. Capture PMKID → 4. Crack Password
```

#### Evil Twin Attack
```text
1. Scan Networks → 2. Select Target → 3. Launch Evil Twin → 4. Capture Credentials
```

### Step 1: Scan for Networks

Launch the app and click "Scan Networks" to discover nearby WiFi networks:

- **SSID** (network name)
- **Channel number**
- **Signal strength**
- **Security type** (WPA/WPA2/WPA3)
- **WPS support** (for WPS attacks)

### Step 2: Select & Capture

Select a network → Choose attack type → Click "Continue to Capture"

**Available Capture Types:**

| Type | Best For | Client Required |
|------|----------|-----------------|
| **4-Way Handshake** | Full password cracking | Yes |
| **PMKID** | Clientless quick attack | No |
| **Passive PMKID** | Background monitoring | No |
| **WPA3-SAE** | Modern WPA3 networks | Yes |

**Before capturing:**

1. **Choose output location**: Click "Choose Location" to save the .pcap file
   - Default: `capture.pcap` in current directory
   - Recommended: Save to Documents or Desktop for easy access
2. **Disconnect from WiFi** (macOS only):
   - Option+Click WiFi icon → "Disconnect"
   - This improves capture reliability

Then click "Start Capture"

The app monitors for handshake frames:

- ✅ **M1** - ANonce (from AP)
- ✅ **M2** - SNonce + MIC (from client)
- 🎉 **Handshake Complete!**

> **macOS Note**: Deauth attacks don't work on Apple Silicon. Manually reconnect a device to trigger the handshake (turn WiFi off/on on your phone).

### Step 3: Crack Password

Navigate to "Crack" tab:

#### Engine Selection

**For Handshake/PMKID cracking:**
- **Native CPU**: Software-only cracking, works everywhere
- **Hashcat GPU**: Requires hashcat + hcxtools installed, 10-100x faster

**For WPS attacks:**
- **Pixie-Dust**: Works offline, instant recovery on vulnerable APs
- **PIN Brute-force**: Online attack against WPS daemon

#### Attack Methods

| Method | Target | Speed | Notes |
|--------|--------|-------|-------|
| **Wordlist Attack** | WPA/WPA2 hashes | Variable | Tests passwords from files like rockyou.txt |
| **Numeric Attack** | PIN codes | ~10K-100K/sec | Tests 8-12 digit PIN codes |
| **WPS Pixie-Dust** | WPS PIN | Instant | Offline attack exploiting weak RNG |
| **WPS PIN Brute-force** | AP WPS daemon | ~1/sec | Online attack (may lock after attempts) |
| **Evil Twin** | User credentials | N/A | Rogue AP with captive portal |

#### Real-time Stats

- Progress bar with percentage
- Current attempts / Total
- Passwords per second
- Live logs (copyable)

## 🛠️ Development

### Prerequisites

- **Rust 1.70+**: Install via [rustup](https://rustup.rs/)
- **Xcode Command Line Tools**: `xcode-select --install`

### Build Commands

```bash
# Development build with fast compile times
cargo build

# Optimized release build
cargo build --release

# Run the app
cargo run --release

# Format code (enforced by CI)
cargo fmt --all

# Lint code (enforced by CI)
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test
```

### Build macOS DMG (Local)

You can build a macOS DMG installer locally from the source code:

```bash
# Build DMG (automatically detects architecture)
./scripts/build_dmg.sh
```

This will create:
- `BrutiFi-{VERSION}-macOS-arm64.dmg` (Apple Silicon)
- `BrutiFi-{VERSION}-macOS-arm64.dmg.sha256` (checksum)

**Note**: The application is signed with ad-hoc signing by default, which is sufficient for local use and testing. No additional code signing is required.

### Optional: Hashcat Integration

For GPU-accelerated cracking, install:

```bash
brew install hashcat hcxtools
```

## 🔐 Security & Legal

### Disclaimer

#### Educational Use Only

This tool is for educational and authorized testing only.

✅ **Legal Uses:**

- Testing your own WiFi network security
- Authorized penetration testing with written permission
- Security research and education
- CTF competitions and challenges

❌ **Illegal Activities:**

- Unauthorized access to networks you don't own
- Intercepting communications without permission
- Any malicious or unauthorized use

**Unauthorized access to computer networks is a criminal offense** in most jurisdictions (CFAA in USA, Computer Misuse Act in UK, etc.). Always obtain explicit written permission before testing.

## 🙏 Acknowledgments & inspiration

This project was inspired by several groundbreaking tools in the WiFi security space:

- [AirJack](https://github.com/rtulke/AirJack) - As `brutifi` but in a Python-based CLI
- [Aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) - Industry-standard WiFi
- [Pyrit](https://github.com/JPaulMora/Pyrit) - Pre-computed tables for WPA-PSK attacks
- [Cowpatty](https://github.com/joswr1ght/cowpatty) - Early WPA-PSK cracking implementation

These tools demonstrated the feasibility of offline WPA/WPA2 password attacks and inspired the creation of a modern, user-friendly desktop application.

Special thanks to the following libraries and tools:

- [Iced](https://github.com/iced-rs/iced) - Cross-platform GUI framework
- [Rayon](https://github.com/rayon-rs/rayon) - Data parallelism library
- [pcap-rs](https://github.com/rust-pcap/pcap) - Rust bindings for libpcap
- [Hashcat](https://github.com/hashcat/hashcat) - GPU-accelerated password recovery
- [hcxtools](https://github.com/ZerBea/hcxtools) - Wireless security auditing tools

## 📄 License

[MIT License](LICENSE) - Use at your own risk
