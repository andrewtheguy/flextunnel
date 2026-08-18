#!/usr/bin/env bash
# Run the Windows CI steps against *this* working tree on the Windows CI VM.
#
#   ci/windows/remote.sh                  # clippy + test over there
#   ci/windows/remote.sh shell            # interactive cmd shell on the VM
#   ci/windows/remote.sh doctor           # report on the VM, change nothing
#   ci/windows/remote.sh clean            # drop the VM's cargo target cache
#
# The far end is the 'winsandbox' ssh alias: a Hyper-V guest running Windows
# Server 2025 with rustup and the MSVC build tools installed machine-wide.
# ci/windows/ci.ps1 is the half that runs over there. How that VM was built and
# provisioned is written up once, in the sibling repo that first used it —
# ../wrustic/docs/windows-vm-ci.md — and is not repeated here; docs/local-ci.md
# covers what is specific to this repo.
#
# This driver is bash, not PowerShell, because the machine driving it is the
# Mac; the far end is still cmd.exe, so remote paths are kept free of spaces and
# quotes (see below) rather than quoted.
#
# The tree is copied rather than fetched from git on purpose — the reason to run
# this instead of pushing a branch is to test what you have in front of you,
# uncommitted changes included.
#
# Overrides:
#   FLEXTUNNEL_WINCI_HOST        ssh target     (default: the 'winsandbox' alias)
#   FLEXTUNNEL_WINCI_REMOTE_DIR  workspace      (default: C:\ci-workspaces\flextunnel)
#   FLEXTUNNEL_WINCI_TARGET_DIR  CARGO_TARGET_DIR (default: C:\ci-cache\flextunnel-target)
set -euo pipefail

usage() { echo "usage: $0 [ci|shell|doctor|clean]" >&2; exit 2; }

command=${1:-ci}
case $command in ci|shell|doctor|clean) ;; *) usage ;; esac

info() { echo "[winci] $*"; }

target=${FLEXTUNNEL_WINCI_HOST:-winsandbox}
remote_dir=${FLEXTUNNEL_WINCI_REMOTE_DIR:-'C:\ci-workspaces\flextunnel'}
# Not the machine-wide C:\ci-cache\target the VM sets — that one belongs to the
# other repo driven onto this same VM, and two workspaces sharing a target
# directory only trade cache churn.
cache_dir=${FLEXTUNNEL_WINCI_TARGET_DIR:-'C:\ci-cache\flextunnel-target'}

# The remote command lines below are assembled by hand and handed to cmd.exe on
# an Administrator session, and two of them are `rmdir /s /q`. A directory
# override carrying a space, a quote or an `&` would not merely fail to parse.
# Take only a plain drive-letter path.
assert_remote_path() {
    local path=$1 name=$2 pattern='^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$'
    if ! [[ $path =~ $pattern ]] || [[ $path == *..* || $path == *\\ ]]; then
        echo "$name must be a drive-letter path of letters, digits, _ . - and \\ with no trailing separator; got: $path" >&2
        exit 2
    fi
}
assert_remote_path "$remote_dir" FLEXTUNNEL_WINCI_REMOTE_DIR
assert_remote_path "$cache_dir" FLEXTUNNEL_WINCI_TARGET_DIR

project_root=$(cd "$(dirname "$0")/../.." && pwd)
ci_script="$remote_dir\\ci\\windows\\ci.ps1"
lock="$remote_dir.lock"

case $command in
    doctor)
        info "checking $target"
        # One ssh call per probe: cmd.exe runs the first line of the command it
        # is handed and drops the rest, so these cannot be one multi-line
        # string. link.exe is not on PATH and is not supposed to be — rustc
        # locates the MSVC toolchain through the registry, so a bare
        # `where link.exe` exits 1 on a healthy VM. Look where it lives instead.
        for probe in 'ver' 'rustc --version' 'cargo --version' 'cargo clippy --version' \
                     'where /r C:\BuildTools\VC\Tools\MSVC link.exe' \
                     'echo machine CARGO_TARGET_DIR=%CARGO_TARGET_DIR%' \
                     "if exist $cache_dir (echo cache: $cache_dir) else (echo cache: none yet)" \
                     "if exist $remote_dir (echo workspace: $remote_dir) else (echo workspace: none yet)"; do
            ssh "$target" "$probe" || true
        done
        exit 0
        ;;
    clean)
        # Under the same lock as a run: the cache being dropped is the one a
        # concurrent run would be compiling into.
        if ! ssh "$target" "mkdir $lock"; then
            echo "$target is busy: $lock already exists — a run is using the cache. If none is, clear it with: ssh $target rmdir $lock" >&2
            exit 1
        fi
        info "dropping $cache_dir on $target"
        ssh "$target" "if exist $cache_dir rmdir /s /q $cache_dir" || true
        ssh "$target" "rmdir $lock"
        info 'done'
        exit 0
        ;;
esac

# A full template rather than -t: BSD and GNU mktemp disagree on what -t means.
archive=$(mktemp "${TMPDIR:-/tmp}/flextunnel-winci.XXXXXX").tgz
# Per-run, so two invocations cannot land on each other's upload in the shared
# login home directory.
remote_archive="flextunnel-winci-src-$$.tgz"

# The workspace and the cargo target directory are single, fixed and shared by
# design — that is what makes a warm run fast. It also means a second run
# starting mid-build would `rmdir /s /q` the tree the first one is compiling.
# Claim the workspace first: mkdir on an existing directory fails, and fails
# atomically, which is all a lock has to do.
if ! ssh "$target" "mkdir $lock"; then
    echo "$target is busy: $lock already exists. Either another run holds the workspace, or one died holding it — clear it with: ssh $target rmdir $lock" >&2
    exit 1
fi

cleanup() {
    rm -f "$archive"
    # Don't leave a copy of the source tree in the login home dir, and never
    # leave the lock behind — a stale one blocks every later run.
    ssh "$target" "del %USERPROFILE%\\$remote_archive & rmdir $lock" >/dev/null 2>&1 || true
}
trap cleanup EXIT

info "packing $(basename "$project_root")"
# --dereference: ship symlinks (AGENTS.md -> CLAUDE.md) as regular files —
# cmd.exe's tar on the VM cannot recreate them, and a Windows checkout would
# have materialized them as files anyway. The long spelling because BSD tar's
# -L is GNU tar's -h, and the driver may be either.
tar -C "$project_root" --dereference \
    --exclude=./target --exclude=./dist --exclude=./tmp --exclude=./.git \
    -czf "$archive" .

info "copying to $target:$remote_dir"
# A relative destination lands in the login user's home directory, which
# sidesteps scp's habit of reading the colon in C:\... as a host separator.
scp -q "$archive" "$target:$remote_archive"

# Replace the workspace outright. tar has no --delete, so unpacking over the old
# tree would leave a file deleted here still sitting there, still getting
# compiled. The cargo target directory lives outside the workspace, so the build
# cache survives this.
ssh "$target" "if exist $remote_dir rmdir /s /q $remote_dir"
ssh "$target" "mkdir $remote_dir"
ssh "$target" "tar -xzf %USERPROFILE%\\$remote_archive -C $remote_dir"

if [ "$command" = shell ]; then
    info "opening a shell on $target at $remote_dir"
    ssh -t "$target" "cd /d $remote_dir && cmd"
    exit 0
fi

info "running ci.ps1 on $target"
# The quoted `set` form, so the value does not pick up the space before `&&`.
ssh "$target" "set \"CARGO_TARGET_DIR=$cache_dir\"&& powershell -NoProfile -ExecutionPolicy Bypass -File $ci_script"
