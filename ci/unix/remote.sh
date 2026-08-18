#!/usr/bin/env bash
# Run the Unix CI steps against *this* working tree on a remote Unix machine.
#
#   ci/unix/remote.sh                     # clippy + test over there
#   ci/unix/remote.sh shell               # interactive shell in the workspace
#   ci/unix/remote.sh doctor              # report on the machine, change nothing
#   ci/unix/remote.sh clean               # drop the machine's cargo target cache
#   ci/unix/remote.sh -H other-box ci     # against a different ssh alias
#
# The host is an ssh alias: 'workstation-wsl' (Debian amd64 under WSL2) is the
# default, and any Unix machine with rustup and a C toolchain works the same
# way — including a Mac (e.g. `-H macwork`), which is how the macOS leg runs
# when the driving machine is not itself a Mac; see docs/local-ci.md.
# ci/unix/ci.sh is the half that runs over there; it picks the platform's steps
# itself.
#
# The tree is copied rather than fetched from git on purpose — the reason to run
# this instead of pushing a branch is to test what you have in front of you,
# uncommitted changes included.
#
# The staging area defaults to codes/staging-area under the remote login user's
# home; override with FLEXTUNNEL_UNIXCI_STAGING (an absolute remote path). It is
# shared with other repos driven the same way, so everything below it is named
# for this one: flextunnel/ is the workspace and is replaced on every run;
# flextunnel-cargo-target/ is CARGO_TARGET_DIR and survives it, which is what
# makes a warm run fast; flextunnel.lock/ is the run lock.
set -euo pipefail

usage() { echo "usage: $0 [-H ssh-host] [ci|shell|doctor|clean]" >&2; exit 2; }

target=${FLEXTUNNEL_UNIXCI_HOST:-workstation-wsl}
if [ "${1:-}" = -H ]; then
    target=${2:-} && [ -n "$target" ] || usage
    shift 2
fi
command=${1:-ci}
case $command in ci|shell|doctor|clean) ;; *) usage ;; esac

info() { echo "[unixci] $*"; }

if [ -n "${FLEXTUNNEL_UNIXCI_STAGING:-}" ]; then
    staging=$FLEXTUNNEL_UNIXCI_STAGING
else
    staging="$(ssh "$target" 'printf %s "$HOME"')/codes/staging-area"
fi

# Every remote line below is a string handed to the login shell on the far end,
# with these paths spliced in between single quotes, and two of them are rm -rf.
# Take only an absolute path of plain characters, at least two components deep
# so no expansion of it can name a filesystem root — the same stance as
# Assert-RemotePath in the Windows driver.
if ! [[ $staging =~ ^(/[A-Za-z0-9._-]+){2,}$ && $staging != *..* ]]; then
    echo "the staging area must be an absolute path of letters, digits, _ . - at least two components deep, with no trailing slash; got: $staging" >&2
    exit 2
fi

workspace=$staging/flextunnel
target_dir=$staging/flextunnel-cargo-target
lock=$staging/flextunnel.lock
project_root=$(cd "$(dirname "$0")/../.." && pwd)

# rustup's bin dir is not on a non-interactive ssh session's PATH; every probe
# and ci.sh itself compensate the same way.
remote_path='export PATH="$HOME/.cargo/bin:$PATH";'

case $command in
    doctor)
        info "checking $target"
        ssh "$target" "$remote_path
            uname -sm
            rustc --version || true
            cargo --version || true
            cargo clippy --version || true
            cc --version 2>&1 | head -1 || true
            echo -n 'staging: '; ls -d '$staging' 2>/dev/null || echo '$staging (absent — created on the first run)'
            du -sh '$target_dir' 2>/dev/null || true"
        exit 0
        ;;
    clean)
        # Under the same lock as a run: the cache being dropped is the one a
        # concurrent run would be compiling into.
        if ! ssh "$target" "mkdir -p '$staging' && mkdir '$lock'"; then
            echo "$target is busy: $lock already exists — a run is using the cache. If none is, clear it with: ssh $target rmdir '$lock'" >&2
            exit 1
        fi
        info "dropping $target_dir on $target"
        ssh "$target" "rm -rf '$target_dir'; rmdir '$lock'"
        info 'done'
        exit 0
        ;;
esac

# A full template rather than -t: BSD and GNU mktemp disagree on what -t means.
# No .tgz suffix appended — tar overwrites the file mktemp made, so cleanup
# removes exactly what was created (an appended suffix would leak the original).
archive=$(mktemp "${TMPDIR:-/tmp}/flextunnel-unixci.XXXXXX")
# Per-run, so two invocations cannot land on each other's upload in the shared
# login home directory.
remote_archive="flextunnel-unixci-src-$$.tgz"

# The workspace and the cargo target directory are single, fixed and shared by
# design. It also means a second run starting mid-build would rm -rf the tree
# the first one is compiling. Claim the workspace first: mkdir on an existing
# directory fails, and fails atomically, which is all a lock has to do.
if ! ssh "$target" "mkdir -p '$staging' && mkdir '$lock'"; then
    echo "$target is busy: $lock already exists. Either another run holds the workspace, or one died holding it — clear it with: ssh $target rmdir '$lock'" >&2
    exit 1
fi

cleanup() {
    rm -f "$archive"
    # Don't leave a copy of the source tree in the login home dir, and never
    # leave the lock behind — a stale one blocks every later run.
    ssh "$target" "rm -f '$remote_archive'; rmdir '$lock'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

info "packing $(basename "$project_root")"
# --dereference for parity with the Windows driver: what lands on the far end
# is the same tree either way, symlinks (AGENTS.md -> CLAUDE.md) resolved. The
# long spelling because BSD tar's -L is GNU tar's -h, and the driver may be
# either.
tar -C "$project_root" --dereference \
    --exclude=./target --exclude=./dist --exclude=./tmp --exclude=./.git \
    -czf "$archive" .

info "copying to $target:$workspace"
scp -q "$archive" "$target:$remote_archive"

# Replace the workspace outright. tar has no --delete, so unpacking over the old
# tree would leave a file deleted here still sitting there, still getting
# compiled. The cargo target directory lives outside the workspace, so the build
# cache survives this.
ssh "$target" "rm -rf '$workspace' && mkdir -p '$workspace' && tar -xzf '$remote_archive' -C '$workspace'"

if [ "$command" = shell ]; then
    info "opening a shell on $target at $workspace"
    ssh -t "$target" "cd '$workspace' && exec \$SHELL -l"
    exit 0
fi

info "running ci.sh on $target"
ssh "$target" "$remote_path cd '$workspace' && CARGO_TARGET_DIR='$target_dir' ./ci/unix/ci.sh"
