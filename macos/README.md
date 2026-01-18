# macOS App Bundle Configuration

This directory contains files for creating a proper macOS application bundle for WiFi Bruteforce.

## Files

### `Info.plist`
Application metadata and permissions declarations:
- Location Services usage descriptions
- Network access permissions
- App bundle configuration

### `entitlements.plist`
Security entitlements for code signing:
- Location Services access
- Network client/server capabilities
- Hardened runtime configuration

### `launcher.sh`
Wrapper script that:
- Requests administrator privileges automatically
- Shows a native macOS dialog for password input
- Launches the app with sudo without terminal

### `build-app.sh`
Build script that creates a complete `.app` bundle:
- Compiles the release binary
- Creates proper bundle structure
- Copies launcher and binary
- Generates Info.plist
- Code signs the app (if certificates available)

## Usage

### Building the App Bundle

```bash
cd /path/to/bruteforce-wifi
./macos/build-app.sh
```

This creates `target/release/WiFi Bruteforce.app`

### Running the App

Double-click the app or run:

```bash
open "target/release/WiFi Bruteforce.app"
```

The launcher will:
1. Show a dialog requesting administrator privileges
2. Prompt for your password
3. Launch the app with sudo automatically
4. Request Location Services permission on first scan

### Manual Launch

You can also run the launcher directly:

```bash
./target/release/WiFi\ Bruteforce.app/Contents/MacOS/launcher
```

## Permissions

### Location Services

The app requires Location Services to access WiFi BSSID information. This is a macOS system requirement.

The permission dialog will appear:
- When the app first tries to scan networks
- In System Settings > Privacy & Security > Location Services

### Administrator Privileges

Packet capture requires root access. The launcher handles this automatically by:
- Showing a native dialog explaining why sudo is needed
- Using macOS's `with administrator privileges` AppleScript feature
- No manual terminal commands required!

## Troubleshooting

### "WiFi Bruteforce.app" is damaged

Run:
```bash
xattr -cr "target/release/WiFi Bruteforce.app"
```

### Location Services permission not showing

Make sure:
1. The app is properly built with `build-app.sh`
2. Info.plist contains the NSLocation* keys
3. You're running the .app bundle, not the raw binary

### Permission denied during capture

The launcher should handle this automatically. If you see this error:
1. Make sure you clicked "Continue" in the password dialog
2. Try running with sudo manually:
   ```bash
   sudo "./target/release/WiFi Bruteforce.app/Contents/MacOS/bruteforce-wifi"
   ```

## Distribution

For distribution, you should:
1. Sign with a Developer ID certificate
2. Notarize the app with Apple
3. Create a DMG installer

Without signing, users will need to:
1. Right-click > Open (first time)
2. Or run `xattr -cr` to remove quarantine
