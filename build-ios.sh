#!/usr/bin/env bash
#
# Build libflextunnel for iOS — both the device (aarch64-apple-ios) and the
# Simulator (aarch64-apple-ios-sim) slices — and bundle them into
# libflextunnel.xcframework in dist/ios, staged with the C header. This is the
# canonical local build output; the CI release workflow zips it into the
# libflextunnel-ios.xcframework.zip asset. The sibling Xcode project
# (../flextunnel-ios) links it via its own Swift package
# (Packages/Flextunnel/Package.swift) — by default a pinned release download, or
# this dist/ios build (reached through a committed symlink) when
# FLEXTUNNEL_LOCAL_XCFRAMEWORK is set (FFI dev). This script only produces
# dist/ios; it does not write into ../flextunnel-ios.
#
# An XCFramework is required (not a lipo "fat" .a): the device and Simulator
# slices are both arm64 on Apple Silicon, and lipo refuses to combine two slices
# of the same architecture. The .xcframework lets one Xcode project link the
# right slice for whichever destination (device or Simulator) is selected.
#
# Unlike a Packet Tunnel Provider, the flextunnel POC app has no Network
# Extension, so the static lib links and runs in the iOS Simulator too.
#
# Usage:
#   ./build-ios.sh            # release build (default)
#   ./build-ios.sh debug      # debug build (faster compile, huge .a)
set -euo pipefail

PROFILE="${1:-release}"
DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGET="aarch64-apple-ios-sim"
# Minimum iOS version. The SwiftUI WebView/WebPage proxy path needs iOS 26.
# Must be <= the Xcode project's deployment target. Override via env.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-26.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "$PROFILE" in
  release) CARGO_FLAGS="--release"; OUT_SUBDIR="release" ;;
  debug)   CARGO_FLAGS="";          OUT_SUBDIR="debug"   ;;
  *) echo "unknown profile '$PROFILE' (use 'release' or 'debug')" >&2; exit 1 ;;
esac

for target in "$DEVICE_TARGET" "$SIM_TARGET"; do
  if ! rustup target list --installed | grep -q "^${target}$"; then
    echo "Installing Rust target ${target}..."
    rustup target add "$target"
  fi
done

for target in "$DEVICE_TARGET" "$SIM_TARGET"; do
  echo "Building libflextunnel.a [$PROFILE] for $target ..."
  cargo build --lib -p flextunnel-ffi ${CARGO_FLAGS} --target "$target"
done

DIST="$SCRIPT_DIR/dist/ios"
XCFRAMEWORK="$DIST/libflextunnel.xcframework"
mkdir -p "$DIST"
cp "ios/flextunnel.h" "$DIST/flextunnel.h"

# Where cargo actually put the .a files: honor CARGO_TARGET_DIR (ci/unix/
# remote.sh redirects the build cache outside the workspace), else ./target.
TARGET_DIR="${CARGO_TARGET_DIR:-$SCRIPT_DIR/target}"

echo "Creating libflextunnel.xcframework ..."
rm -rf "$XCFRAMEWORK"
xcodebuild -create-xcframework \
  -library "$TARGET_DIR/${DEVICE_TARGET}/${OUT_SUBDIR}/libflextunnel.a" -headers "ios" \
  -library "$TARGET_DIR/${SIM_TARGET}/${OUT_SUBDIR}/libflextunnel.a"    -headers "ios" \
  -output "$XCFRAMEWORK"

echo "Staged: $XCFRAMEWORK"
echo "        $DIST/flextunnel.h"
echo
echo "For local iOS FFI dev, build the app against this xcframework with:"
echo "    cd ../flextunnel-ios"
echo "    FLEXTUNNEL_LOCAL_XCFRAMEWORK=1 xcodegen generate"
echo "    FLEXTUNNEL_LOCAL_XCFRAMEWORK=1 xcodebuild -project Flextunnel.xcodeproj \\"
echo "        -scheme FlextunnelApp -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.2' build"
echo "Done."
