//! Advisory single-instance file lock for the server binary.
//!
//! Uses std's native advisory file locking ([`std::fs::File::try_lock`], stable
//! since Rust 1.89) — no external crate. The lock is held for the process
//! lifetime via the open [`File`] and released automatically on exit or crash
//! (the OS drops the advisory lock when the fd closes), so a stale lock file
//! never wedges a restart.
//!
//! This module owns only the mechanics; the caller chooses the *scope* by
//! passing the lock path. The server uses a per-user path (one server per user).
//!
//! # Alternative mechanisms (if the file lock ever becomes inconvenient)
//!
//! A file lock was chosen because it is std-only, portable, and — crucially —
//! auto-released when the fd closes on exit/crash, so it never leaves stale state
//! that wedges a restart (a leftover lock *file* is harmless; the lock is the fd,
//! not the file's existence). Its only wart is filesystem path/permission friction.
//! If that friction ever outweighs the portability, these are the cleaner
//! OS-native singleton primitives.
//! They are all also auto-released on process death, which is the property that
//! disqualifies PID files and POSIX/SysV semaphores (both persist and go stale):
//!
//! | OS          | Cleanest native choice                                    |
//! |-------------|-----------------------------------------------------------|
//! | Linux       | abstract-namespace Unix socket (`\0flextunnel`) —         |
//! |             | no filesystem entry, no stale socket file, machine-wide.  |
//! | macOS / BSD | loopback UDP port (`127.0.0.1:N`); UDP dodges TCP         |
//! |             | `TIME_WAIT`. Or, for a launchd-managed daemon, rely on    |
//! |             | launchd's own single-instance-per-job guarantee and skip  |
//! |             | the lock entirely. (No abstract UDS on macOS; a Mach       |
//! |             | bootstrap port is the true analog but needs Mach FFI.)    |
//! | Windows     | named mutex (`Global\flextunnel`) or loopback UDP.        |
//!
//! A single portable option across all three is **loopback UDP on a fixed high
//! port**: no filesystem at all, machine-wide by nature, auto-released. Its only
//! risk is an unrelated app squatting the port (a false "already running"), which
//! is negligible under this project's "catch accidental misconfiguration" trust
//! model. The per-OS split above is only worth it if that risk is unacceptable.

use anyhow::{Context, Result};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// Holds the lock file open for the lifetime of the process. The lock is held by
/// the open file descriptor and released when this is dropped.
pub struct InstanceLock {
    #[allow(dead_code)] // kept open to hold the advisory lock; released on drop
    file: File,
}

impl InstanceLock {
    /// Acquire an advisory single-instance lock at `path`. Creates the parent
    /// directory and the file as needed, then records the current PID for
    /// operator visibility. Fails if the path can't be opened, or with
    /// `contended_msg` if another process already holds the lock.
    ///
    /// The scope owns its own single-user path (the server's per-user config dir),
    /// so ordinary umask-created permissions suffice — no cross-user sharing is
    /// required.
    pub fn acquire(path: &Path, contended_msg: &str) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create the lock directory {}", parent.display())
            })?;
        }
        // Open or create the lock file WITHOUT truncating — truncation must happen
        // only after we hold the lock, so a concurrent holder's PID isn't clobbered.
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(false);
        let mut file = opts
            .open(path)
            .with_context(|| format!("Failed to open the lock file {}", path.display()))?;

        match file.try_lock() {
            Ok(()) => {
                // We hold the lock: record our PID for operator visibility.
                let _ = file.set_len(0);
                let _ = file.seek(SeekFrom::Start(0));
                let _ = writeln!(file, "{}", std::process::id());
                log::debug!("Acquired single-instance lock: {}", path.display());
                Ok(Self { file })
            }
            Err(TryLockError::WouldBlock) => anyhow::bail!("{contended_msg}"),
            Err(TryLockError::Error(e)) => Err(e).with_context(|| {
                format!("Failed to acquire the single-instance lock ({})", path.display())
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// While one lock is held, a second acquisition of the same path must be
    /// rejected (advisory locks conflict across open file descriptions, even in
    /// one process); after the first is dropped, acquiring succeeds again.
    #[test]
    fn second_acquire_rejected_while_held() {
        // Unique per-run path: the fixed name would collide across concurrent
        // `cargo test` processes (advisory locks conflict across processes), making
        // the "first acquire" flakily fail. PID + a high-res timestamp is enough.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir()
            .join(format!("flextunnel-instance-lock-test-{}-{nanos}.lock", std::process::id()));
        let first = InstanceLock::acquire(&path, "held").expect("first acquire");
        assert!(
            InstanceLock::acquire(&path, "held").is_err(),
            "a second acquire must fail while the lock is held"
        );
        drop(first);
        // Released: acquiring again should now succeed.
        assert!(
            InstanceLock::acquire(&path, "held").is_ok(),
            "acquire should succeed after the lock is released"
        );
        let _ = std::fs::remove_file(&path);
    }
}
