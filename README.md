# BrutiFi 🔐

> Simple desktop application for WPA/WPA2 password cracking on macOS

[![Release](https://github.com/maxgfr/bruteforce-wifi/actions/workflows/release.yml/badge.svg)](https://github.com/maxgfr/bruteforce-wifi/releases)
[![CI](https://github.com/maxgfr/bruteforce-wifi/actions/workflows/ci.yml/badge.svg)](https://github.com/maxgfr/bruteforce-wifi/actions)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**⚠️ EDUCATIONAL USE ONLY - UNAUTHORIZED ACCESS IS ILLEGAL ⚠️**

A simple macOS desktop app for testing WiFi password security. Scan networks, capture handshakes, and crack passwords using CPU or GPU acceleration.

## ✨ Features

- 🖥️ **Simple Desktop GUI** - Clean 2-screen interface built with Iced
- 🚀 **Dual Cracking Engines**:
  - **Native CPU**: Custom PBKDF2 (~10K-100K passwords/sec)
  - **Hashcat GPU**: 10-100x faster with automatic device detection
- 📡 **WiFi Network Scanning** - Real-time discovery with channel detection
- 🎯 **Two Attack Methods**:
  - **4-Way Handshake**: Traditional EAPOL frame capture (requires client reconnection)
  - **PMKID**: Clientless attack from beacon frames (no clients needed)
- 🔑 **Two Crack Modes**:
  - 🔢 Numeric bruteforce (8-12 digit PINs)
  - 📋 Wordlist attacks (rockyou.txt, custom lists)
- 📊 **Live Progress** - Real-time speed, attempts, and ETA
- 🔒 **100% Offline** - No data transmitted

## 📦 Installation

### macOS

#### Quick Installation

1. Download the DMG from the latest release (Apple Silicon or Intel)
2. Open the DMG and drag **BrutiFi.app** to **Applications**
3. Launch the app — macOS will ask for admin password to enable capture

#### Remove Quarantine (Required for GitHub downloads)

```bash
xattr -dr com.apple.quarantine /Applications/BrutiFi.app
```

### From Source

```bash
git clone https://github.com/maxgfr/bruteforce-wifi.git
cd bruteforce-wifi
cargo build --release
./target/release/brutifi
```

## 🚀 Usage

### Simple 2-Step Workflow

```
1. Scan & Capture → Generates .pcap file with handshake/PMKID
2. Crack → Bruteforce password from .pcap
```

### Step 1: Scan & Capture

1. Click **"Scan"** to discover nearby WiFi networks
2. Select a target network from the list
3. (Optional) Disconnect from WiFi for better capture: `Option+Click WiFi → Disconnect`
4. Click **"Start Capture"**

The app automatically captures either:
- ✅ **PMKID** (clientless, instant)
- ✅ **4-Way Handshake** (M1 + M2 frames)

> **macOS Note**: Deauth attacks don't work on Apple Silicon. Manually reconnect a device to trigger handshake (turn phone WiFi off/on).

### Step 2: Crack Password

1. Navigate to **"Crack"** tab
2. Select cracking engine:
   - **Native CPU**: Works everywhere
   - **Hashcat GPU**: 10-100x faster (requires `brew install hashcat hcxtools`)
3. Choose attack method:
   - **Numeric**: Tests 8-12 digit PIN codes
   - **Wordlist**: Tests passwords from file (e.g., rockyou.txt)
4. Click **"Start Cracking"**

Watch real-time progress with speed and ETA!

## 🛠️ Development

### Prerequisites

- **Rust 1.70+**: Install via [rustup](https://rustup.rs/)
- **Xcode Command Line Tools**: `xcode-select --install`

### Build Commands

```bash
# Development build
cargo build

# Release build
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

### Optional: Hashcat GPU Acceleration

```bash
brew install hashcat hcxtools
```

## 🔐 Security & Legal

### Disclaimer

**Educational Use Only**

✅ **Legal Uses:**
- Testing your own WiFi network
- Authorized penetration testing with written permission
- Security research and education

❌ **Illegal Activities:**
- Unauthorized network access
- Intercepting communications without permission

**Unauthorized access is a criminal offense.** Always obtain explicit written permission.

## 🔧 Alternatives

**Looking for more advanced features?**

BrutiFi focuses on **simplicity** with just 2 core attacks (PMKID + Handshake). For a more comprehensive WiFi auditing tool with additional attack vectors, check out:

- **[Wifite2](https://github.com/kimocoder/wifite2)** - Complete automated wireless auditing tool
  - WPS attacks (Pixie Dust, PIN brute-force)
  - WPA3 attacks (Transition downgrade, SAE)
  - Evil Twin phishing
  - Multiple attack automation
  - Linux-focused CLI tool

## 🙏 Acknowledgments

Inspired by:
- [AirJack](https://github.com/rtulke/AirJack) - Python-based CLI inspiration
- [Aircrack-ng](https://github.com/aircrack-ng/aircrack-ng) - Industry standard
- [Hashcat](https://github.com/hashcat/hashcat) - GPU acceleration
- [hcxtools](https://github.com/ZerBea/hcxtools) - Format conversion

Built with:
- [Iced](https://github.com/iced-rs/iced) - GUI framework
- [Rayon](https://github.com/rayon-rs/rayon) - Parallelism
- [pcap-rs](https://github.com/rust-pcap/pcap) - Packet capture

## 📄 License

[MIT License](LICENSE) - Use at your own risk
