#!/usr/bin/env bash
# The steps from .github/workflows/ci.yml, in the same order, with the same
# flags — the `linux` job on Linux, the `macos` + `verify-ios-xcframework` jobs
# on macOS. When this file and that workflow disagree, the workflow is right and
# this is stale; it exists to say what CI will say before CI is asked.
#
# This runs natively on whatever Unix machine it is invoked on: a CI box (see
# ci/unix/remote.sh) or a dev machine. It installs nothing and changes no
# machine state, so running it locally is safe.
#
# Not covered here, on purpose: release-profile builds, .dmg/.msi packaging and
# the Docker images, all of which belong to release.yml.
set -euo pipefail

# Invoked over ssh the working directory is the login user's home, not the
# checkout, so anchor to the repo root this script sits in. A non-interactive
# ssh shell also skips the profile that puts rustup's bin dir on PATH.
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

step() {
    local name=$1; shift
    echo ''
    echo "== $name =="
    echo "   cargo $*"
    cargo "$@"
}

echo '== toolchain =='
uname -sm
rustc --version
cargo --version
cargo clippy --version
[ -n "${CARGO_TARGET_DIR:-}" ] && echo "   CARGO_TARGET_DIR=$CARGO_TARGET_DIR"

if [ "$(uname -s)" = Darwin ]; then
    # The macos job: the host clippy is what type-checks flextunnel-desktop's
    # macOS backend (tray + keychain), which the Linux job never sees.
    step 'Clippy' clippy --workspace --all-targets -- -D warnings
    step 'Test' test -p flextunnel-core -p flextunnel-cli -p flextunnel-desktop

    # The verify-ios-xcframework job. Needs Xcode (xcodebuild) and the two iOS
    # Rust targets — build-ios.sh adds the targets itself, but nothing here can
    # conjure up Xcode, so a machine without it skips loudly rather than failing.
    # FLEXTUNNEL_CI_SKIP_IOS=1 skips it on a machine that does have Xcode.
    if [ -n "${FLEXTUNNEL_CI_SKIP_IOS:-}" ]; then
        echo ''
        echo '== iOS xcframework (debug) =='
        echo '   SKIPPED: FLEXTUNNEL_CI_SKIP_IOS is set'
    elif ! command -v xcodebuild >/dev/null; then
        echo ''
        echo '== iOS xcframework (debug) =='
        echo '   SKIPPED: no xcodebuild on this machine'
    else
        echo ''
        echo '== iOS xcframework (debug) =='
        echo '   ./build-ios.sh debug'
        # build-ios.sh builds into ./target and stages ./dist/ios by relative
        # path; CARGO_TARGET_DIR (set by remote.sh) still redirects the former.
        ./build-ios.sh debug
    fi
else
    # The linux job: flextunnel-desktop is macOS/Windows only (tray + keychain
    # backends) and is excluded; flextunnel-ffi still type-checks here.
    step 'Clippy' clippy --workspace --exclude flextunnel-desktop --all-targets -- -D warnings
    step 'Test' test -p flextunnel-core -p flextunnel-cli
fi

echo ''
echo 'all steps passed'
