/*!
 * GUI Screens
 *
 * Each screen represents a step in the WiFi cracking workflow:
 * 1. Scan & Capture - Discover networks, detect vulnerabilities, and capture handshake
 * 2. Crack - Bruteforce the password
 */

pub mod crack;
pub mod scan_capture;

pub use crack::{CrackEngine, CrackMethod, CrackScreen};
pub use scan_capture::{HandshakeProgress, ScanCaptureScreen};
