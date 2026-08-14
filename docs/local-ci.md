# Running CI locally

`.github/workflows/ci.yml` runs the same two steps — clippy with `-D warnings`,
then the tests — on a Linux, a macOS and a Windows runner, plus an iOS
xcframework build on macOS. The three platforms are not interchangeable: the
host clippy is the only thing that type-checks `flextunnel-desktop`'s
macOS/Windows tray + keychain backends, and `flextunnel-desktop` is excluded
entirely on Linux. So a change that compiles here can still fail there.

`ci/` runs all of it locally, against the working tree as it is — uncommitted
changes included — so a platform-specific failure can be found without pushing a
branch and waiting.

| Platform | Machine | Entry point |
| --- | --- | --- |
| macOS | this one, natively | `ci/unix/ci.sh` |
| Linux | `workstation-wsl` (Debian amd64 under WSL2) | `ci/unix/remote.sh` |
| Windows | `winsandbox` (Windows Server 2025 VM) | `ci/windows/remote.sh` |

```sh
ci/all.sh                  # all three, concurrently
ci/all.sh linux windows    # only these
```

`ci/all.sh` captures each platform's output and replays it in full once
everything has finished — three machines writing to one terminal at once would
interleave into nonsense — then prints a summary of exit codes. To watch one
platform live, run its script directly.

## The two halves

Each remote platform is two scripts, and the split is the point:

- `ci/unix/ci.sh` and `ci/windows/ci.ps1` run **natively on the far end**. They
  are the workflow's steps, in the same order, with the same flags. They install
  nothing and change no machine state, so either can also be run directly on a
  dev box — `ci/unix/ci.sh` *is* the macOS row of the table above.
- `ci/unix/remote.sh` and `ci/windows/remote.sh` run **here**. They pack the
  working tree, ship it over ssh, and invoke the script above.

When a `ci.*` script and the workflow disagree, the workflow is right and the
script is stale. Keep them in step by hand; nothing enforces it.

Both remote drivers take the same four commands:

```sh
ci/unix/remote.sh            # or: ci ...  clippy + test over there
ci/unix/remote.sh shell      # interactive shell in the remote workspace
ci/unix/remote.sh doctor     # report on the machine, change nothing
ci/unix/remote.sh clean      # drop the machine's cargo target cache
```

`ci/unix/remote.sh -H some-other-host` points the Unix driver at a different ssh
alias; any Unix machine with rustup and a C toolchain works.

## What runs where

Mirroring the jobs in `ci.yml`:

- **Linux** — `cargo clippy --workspace --exclude flextunnel-desktop
  --all-targets -- -D warnings`, then `cargo test -p flextunnel-core -p
  flextunnel-cli`. `flextunnel-desktop` is macOS/Windows only;
  `flextunnel-ffi` (the iOS staticlib) still type-checks on a Linux host.
- **macOS** — clippy over the whole workspace, tests for core + cli + desktop,
  then `./build-ios.sh debug` (the `verify-ios-xcframework` job). The iOS step
  skips itself, loudly, on a machine with no `xcodebuild`; set
  `FLEXTUNNEL_CI_SKIP_IOS=1` to skip it on a machine that has one. That step only
  proves the xcframework *builds*; whether an iOS-affecting change still compiles
  and links into the app, and whether it runs on a real phone, is the sibling
  repo's `../flextunnel-ios/ci/` (`ci/ci.sh ffi` builds this working tree and
  links the app against it — see that repo's `docs/local-ci.md`).
- **Windows** — clippy over the whole workspace, tests for core + cli + desktop.

Deliberately **not** here: release-profile builds, `.dmg`/`.msi` packaging, the
iOS release zip and the Docker images. Those belong to `release.yml`, they are
slow, and none of them catch anything the steps above miss.

## Where the trees land

The tree is copied, not fetched from git — the reason to run this instead of
pushing a branch is to test what is in front of you. On both remotes the
workspace is replaced outright on every run (`tar` has no `--delete`, so
unpacking over the old tree would leave a file you deleted here still sitting
there and still being compiled), while `CARGO_TARGET_DIR` points *outside* the
workspace so the build cache survives the swap. That is what makes a warm run
fast and a cold one slow.

| | Linux (`workstation-wsl`) | Windows (`winsandbox`) |
| --- | --- | --- |
| workspace | `~/codes/staging-area/flextunnel` | `C:\ci-workspaces\flextunnel` |
| build cache | `~/codes/staging-area/flextunnel-cargo-target` | `C:\ci-cache\flextunnel-target` |
| lock | `~/codes/staging-area/flextunnel.lock` | `C:\ci-workspaces\flextunnel.lock` |
| overrides | `FLEXTUNNEL_UNIXCI_HOST`, `FLEXTUNNEL_UNIXCI_STAGING` | `FLEXTUNNEL_WINCI_HOST`, `FLEXTUNNEL_WINCI_REMOTE_DIR`, `FLEXTUNNEL_WINCI_TARGET_DIR` |

Both staging areas are shared with other repos driven onto the same boxes, which
is why every path under them is named for this one — including the Windows build
cache, which deliberately is *not* the machine-wide `C:\ci-cache\target` that VM
sets.

**One run per machine at a time.** The workspace and the build cache are single
and shared, so a second run starting mid-build would delete the tree the first
is compiling. Each driver claims a lock directory with `mkdir` (which fails,
atomically, if it exists) and drops it on the way out. `clean` takes the same
lock — the cache it drops is the one a concurrent run would be compiling into.
If a run is killed hard enough to skip the release, the next one says so and
prints the command to clear the lock.

## The two machines

**`workstation-wsl`** is a Debian install under WSL2, reached by the ssh alias of
that name. It needs rustup (with clippy) and a C toolchain and nothing else —
the desktop crate, which is what would drag in dbus and a tray, is excluded on
Linux. `ci/unix/remote.sh doctor` reports what is there.

**`winsandbox`** is a Hyper-V guest running Windows Server 2025 with the VS Build
Tools and rustup installed **machine-wide** — a per-profile rustup install would
be invisible over ssh. How that VM was built, provisioned and hardened is
written up once, in the sibling repo that first used it:
[`../wrustic/docs/windows-vm-ci.md`](https://github.com/andrewtheguy/wrustic/blob/main/docs/windows-vm-ci.md).
Two things from it are worth repeating because they cost an afternoon each:
sshd captures its environment when the service starts, so a machine-scoped
`PATH` or `CARGO_*` change is invisible over ssh until `Restart-Service sshd`;
and the guest needs a page file, or parallel `rustc` processes exhaust the commit
limit and fail with what looks like a corrupted toolchain.

The Windows driver is bash rather than PowerShell because the machine driving it
is the Mac. The far end is still `cmd.exe`, so remote paths are kept free of
spaces and quotes and are validated against that shape before use — they get
interpolated into command lines that include `rmdir /s /q`.

## Where this is not the real runner

Worth knowing before trusting a green run:

- **The toolchains float and are not pinned.** Rust on each box is whatever
  `rustup update` last fetched; on GitHub it is whatever the image ships. Run
  `doctor` on both remotes rather than trusting a version written down here.
- **The Windows VM is a bare Server install** — MSVC, the Windows SDK, rustup,
  nothing else. `windows-latest` carries an enormous preinstalled toolbox, so a
  test that quietly depends on some other tool passes there and fails here. It
  also runs as Administrator, which CI does not.
- **Linux is WSL2, not a GitHub Ubuntu runner** — a different kernel, and a
  Debian userland rather than Ubuntu.
- **macOS is this dev box**, with your Xcode, your keychain and your logged-in
  GUI session — the closest of the three to its runner and still not it.
