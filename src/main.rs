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
mod workers_optimized;

use app::BruteforceApp;
use iced::Size;
use std::panic;

/// Check if the application is running with root privileges
#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

/// Setup panic handler to show errors instead of silent exit
fn setup_panic_handler() {
    let default_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // Log to stderr
        eprintln!("\n");
        eprintln!("Application Error");
        eprintln!("=================");

        if let Some(location) = panic_info.location() {
            eprintln!(
                "Location: {}:{}:{}",
                location.file(),
                location.line(),
                location.column()
            );
        }

        if let Some(message) = panic_info.payload().downcast_ref::<&str>() {
            eprintln!("Message: {}", message);
        } else if let Some(message) = panic_info.payload().downcast_ref::<String>() {
            eprintln!("Message: {}", message);
        }

        eprintln!("\nPlease report this issue at:");
        eprintln!("https://github.com/maxgfr/bruteforce-wifi/issues\n");

        // Call default handler for stack trace
        default_hook(panic_info);
    }));
}

fn main() -> iced::Result {
    // Setup panic handler first
    setup_panic_handler();

    // Check for root privileges
    let is_root = is_root();

    // Print startup info
    eprintln!("\nBrutyFi v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("================================\n");

    // macOS-specific guidance
    #[cfg(target_os = "macos")]
    {
        eprintln!("macOS Permission Guide:");
        eprintln!("------------------------");
        eprintln!("  Capture:  Requires root (sudo) for monitor mode");
        eprintln!("            Note: Apple Silicon Macs have limited capture support");
        eprintln!();
        eprintln!("  Crack:    Works without any special permissions");
        eprintln!("================================\n");

        if is_root {
            eprintln!("Running as root. Capture mode is available.\n");
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        if !is_root {
            eprintln!("WARNING: Not running with administrator privileges!");
            eprintln!("  - Network scanning may have limited results");
            eprintln!("  - Packet capture will not work");
            eprintln!();
            eprintln!("To run with admin privileges:");
            eprintln!("  sudo ./target/release/brutifi");
            eprintln!();
            eprintln!("Note: Crack mode works without admin privileges.");
            eprintln!("================================\n");
        } else {
            eprintln!("Running with administrator privileges.\n");
        }
    }

    // Run the GUI application
    iced::application("BrutiFi", BruteforceApp::update, BruteforceApp::view)
        .subscription(BruteforceApp::subscription)
        .theme(BruteforceApp::theme)
        .window_size(Size::new(900.0, 700.0))
        .run_with(move || BruteforceApp::new(is_root))
}
