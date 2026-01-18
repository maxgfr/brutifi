#!/bin/bash
#
# Build macOS .app bundle with proper configuration
#

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
APP_NAME="WiFi Bruteforce"
BUNDLE_ID="com.maxgfr.bruteforce-wifi"
# Extract version from Cargo.toml
VERSION=$(grep "^version = " "$PROJECT_ROOT/Cargo.toml" | head -n 1 | sed 's/version = "\(.*\)"/\1/')

echo "🔨 Building WiFi Bruteforce.app v${VERSION}..."

# Build release binary
cd "$PROJECT_ROOT"
echo "📦 Compiling release binary..."
cargo build --release

# Create app bundle structure
APP_DIR="$PROJECT_ROOT/target/release/$APP_NAME.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"

echo "📁 Creating app bundle structure..."
rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR"
mkdir -p "$RESOURCES_DIR"

# Copy binary
echo "📋 Copying binary..."
cp "$PROJECT_ROOT/target/release/bruteforce-wifi" "$MACOS_DIR/"

# Copy launcher script
echo "📋 Copying launcher..."
cp "$SCRIPT_DIR/launcher.sh" "$MACOS_DIR/launcher"
chmod +x "$MACOS_DIR/launcher"

# Generate Info.plist
echo "📄 Generating Info.plist..."
cat > "$CONTENTS_DIR/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>launcher</string>
    <key>CFBundleIdentifier</key>
    <string>$BUNDLE_ID</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>$APP_NAME</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>LSUIElement</key>
    <false/>
    
    <!-- Location Services Permission -->
    <key>NSLocationWhenInUseUsageDescription</key>
    <string>WiFi Bruteforce needs access to Location Services to scan and display WiFi network BSSIDs (MAC addresses). This is required by macOS to access WiFi details.</string>
    
    <key>NSLocationAlwaysAndWhenInUseUsageDescription</key>
    <string>WiFi Bruteforce needs access to Location Services to scan WiFi networks and capture handshakes. This is a system requirement for accessing WiFi information.</string>
    
    <!-- Network -->
    <key>NSLocalNetworkUsageDescription</key>
    <string>WiFi Bruteforce needs network access to scan WiFi networks and capture packets.</string>
    
    <!-- App Category -->
    <key>LSApplicationCategoryType</key>
    <string>public.app-category.developer-tools</string>
</dict>
</plist>
EOF

# Sign the app if developer ID is available (optional)
if command -v codesign &> /dev/null; then
    echo "🔐 Code signing app..."
    # Try to sign with ad-hoc signature
    codesign --force --deep --sign - "$APP_DIR" 2>/dev/null || echo "⚠️  Code signing skipped (no certificate)"
fi

echo "✅ App bundle created at: $APP_DIR"
echo ""
echo "To run:"
echo "  open '$APP_DIR'"
echo ""
echo "Or from terminal:"
echo "  '$APP_DIR/Contents/MacOS/launcher'"
