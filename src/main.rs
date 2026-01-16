/*!
 * WiFi Bruteforce Desktop GUI Application
 *
 * Built with Iced framework for macOS/Linux/Windows support.
 * Provides a user-friendly interface for:
 * - Scanning WiFi networks
 * - Capturing WPA/WPA2 handshakes
 * - Cracking passwords (numeric or wordlist)
 */

mod app;
mod screens;
mod theme;
mod workers;

use app::BruteforceApp;
use iced::Size;

/// Check if the application is running with root privileges
#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

fn main() -> iced::Result {
    // Check for root privileges
    let is_root = is_root();

    if !is_root {
        eprintln!("\n⚠️  WARNING: Not running with administrator privileges!");
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        eprintln!("Some features require admin/root privileges:");
        eprintln!("  • Network scanning");
        eprintln!("  • Packet capture");
        eprintln!();
        eprintln!("🔧 How to run with administrator privileges:");
        eprintln!();
        eprintln!("METHOD 1 - Using helper script (Recommended):");
        eprintln!("  chmod +x run-with-sudo.sh");
        eprintln!("  ./run-with-sudo.sh");
        eprintln!();
        eprintln!("METHOD 2 - Direct sudo:");
        eprintln!("  sudo -E ./target/release/bruteforce-wifi");
        eprintln!("  (Note: -E preserves environment for GUI)");
        eprintln!();
        eprintln!("METHOD 3 - Build and run:");
        eprintln!("  cargo build --release");
        eprintln!("  sudo -E ./target/release/bruteforce-wifi");
        eprintln!();
        eprintln!("💡 The app will still open, but scan/capture will be limited.");
        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    }

    iced::application(
        "WiFi Bruteforce Tool",
        BruteforceApp::update,
        BruteforceApp::view,
    )
    .subscription(BruteforceApp::subscription)
    .theme(BruteforceApp::theme)
    .window_size(Size::new(900.0, 700.0))
    .run_with(move || BruteforceApp::new(is_root))
}
