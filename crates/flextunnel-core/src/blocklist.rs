//! Persistent duplicate-id blocklist for the server.
//!
//! The blocklist is a small JSON file (default
//! `~/.config/flextunnel/blocklist.json`) that records identities involved in a
//! **duplicate-id conflict** — a guard rail against accidental misconfiguration
//! (see `docs/architecture.md`, "Security model"). It holds two kinds of entry:
//!
//! * **`blocked_clients`** — iroh node ids the server saw as a *confirmed
//!   duplicate client* (two live processes presenting the same node id). Because
//!   client ids are ephemeral (a fresh key per process), such an id never
//!   recurs, so these entries are mostly an **audit record**; they are still
//!   rejected up-front if seen again.
//! * **`conflicted_server_ids`** — the server's *own* `EndpointId` when it
//!   detects it is a duplicate of another server sharing its secret key. On the
//!   next launch the server refuses to start if its id is listed here, forcing an
//!   operator to resolve the conflict and clear the entry.
//!
//! Writes are atomic (temp file + rename) so a crash can never leave a truncated
//! file, and the file loads as empty when absent (normal first run).

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// One blocklist entry: an identity plus why/when it was recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEntry {
    /// Canonical identifier: an iroh `EndpointId`.
    pub id: String,
    /// Human-readable reason the id was blocked (for the operator).
    pub reason: String,
    /// Unix time (milliseconds) the conflict was detected.
    pub detected_at_ms: u64,
}

/// The serialized on-disk shape of the blocklist.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct BlockListData {
    blocked_clients: Vec<BlockEntry>,
    conflicted_server_ids: Vec<BlockEntry>,
}

/// In-memory blocklist bound to the file it was loaded from.
#[derive(Debug, Clone)]
pub struct BlockList {
    path: PathBuf,
    data: BlockListData,
}

/// Default blocklist path (`~/.config/flextunnel/blocklist.json`), matching the
/// config-file convention in [`crate::config`]. `None` if the home dir is
/// unknown.
pub fn default_blocklist_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| {
        home.join(".config")
            .join("flextunnel")
            .join("blocklist.json")
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl BlockList {
    /// Load the blocklist from `path`. A missing file yields an empty blocklist
    /// (the normal first-run case); a present-but-unparseable file is an error so
    /// corruption fails loudly rather than silently dropping blocks.
    pub fn load(path: PathBuf) -> io::Result<Self> {
        let data = match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).map_err(|e| {
                io::Error::other(format!(
                    "Failed to parse blocklist {}: {e}",
                    path.display()
                ))
            })?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BlockListData::default(),
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!("Failed to read blocklist {}: {e}", path.display()),
                ));
            }
        };
        Ok(Self { path, data })
    }

    /// The file this blocklist is backed by.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of blocked client ids (for the status page — entries are not
    /// exposed).
    pub fn blocked_client_count(&self) -> usize {
        self.data.blocked_clients.len()
    }

    /// Number of recorded conflicted (self-blocked) server ids.
    pub fn conflicted_server_count(&self) -> usize {
        self.data.conflicted_server_ids.len()
    }

    /// Whether a client node id is blocked.
    pub fn is_client_blocked(&self, id: &str) -> bool {
        self.data.blocked_clients.iter().any(|e| e.id == id)
    }

    /// Whether a server id is recorded as conflicted (self-block on startup).
    pub fn is_server_conflicted(&self, id: &str) -> bool {
        self.data.conflicted_server_ids.iter().any(|e| e.id == id)
    }

    /// Record a confirmed duplicate client id. Returns `true` if newly added
    /// (a caller should persist only when something changed).
    pub fn add_blocked_client(&mut self, id: &str, reason: impl Into<String>) -> bool {
        if self.is_client_blocked(id) {
            return false;
        }
        self.data.blocked_clients.push(BlockEntry {
            id: id.to_string(),
            reason: reason.into(),
            detected_at_ms: now_ms(),
        });
        true
    }

    /// Record the server's own id as conflicted. Returns `true` if newly added.
    pub fn add_conflicted_server(&mut self, id: &str, reason: impl Into<String>) -> bool {
        if self.is_server_conflicted(id) {
            return false;
        }
        self.data.conflicted_server_ids.push(BlockEntry {
            id: id.to_string(),
            reason: reason.into(),
            detected_at_ms: now_ms(),
        });
        true
    }

    /// Serialize the current state to pretty JSON (cheap; safe to call under a
    /// lock, then write the returned string outside it via [`write_atomic`]).
    pub fn to_json(&self) -> io::Result<String> {
        serde_json::to_string_pretty(&self.data).map_err(io::Error::other)
    }
}

/// Atomically write `json` to `path`: create parent dirs, write a sibling temp
/// file, then `rename` it into place so a reader never sees a partial file.
///
/// The temp file name is **unique per writer** (pid + a process-local counter),
/// so two writers racing on the same `path` — concurrent tasks, or two server
/// processes sharing one blocklist file — never write the same temp file and so
/// can't corrupt each other's snapshot. Because `rename` is atomic, the final
/// file is always a complete, valid snapshot from one of the writers (a
/// simultaneous write from a second process can still be a last-writer-wins lost
/// update, but never a torn/corrupt file). Callers that need writes ordered
/// within a process should hold their in-memory lock across this call.
pub fn write_atomic(path: &Path, json: &str) -> io::Result<()> {
    static SEQ: AtomicU64 = AtomicU64::new(0);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Sibling temp in the same directory so the rename is atomic (same
    // filesystem), with a unique suffix so concurrent writers don't collide.
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.{seq}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);

    if let Err(e) = std::fs::write(&tmp, json) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("flextunnel-blocklist-test-{name}.json"))
    }

    #[test]
    fn missing_file_loads_empty() {
        let path = tmp_path("missing");
        let _ = std::fs::remove_file(&path);
        let bl = BlockList::load(path).unwrap();
        assert!(!bl.is_client_blocked("anything"));
        assert!(!bl.is_server_conflicted("anything"));
    }

    #[test]
    fn add_persist_and_reload_roundtrip() {
        let path = tmp_path("roundtrip");
        let _ = std::fs::remove_file(&path);

        let mut bl = BlockList::load(path.clone()).unwrap();
        assert!(bl.add_blocked_client("client-node-id", "duplicate client"));
        assert!(bl.add_conflicted_server("server-endpoint-id", "duplicate server"));
        // Idempotent: a repeat is not re-added.
        assert!(!bl.add_blocked_client("client-node-id", "again"));
        write_atomic(bl.path(), &bl.to_json().unwrap()).unwrap();

        let reloaded = BlockList::load(path.clone()).unwrap();
        assert!(reloaded.is_client_blocked("client-node-id"));
        assert!(reloaded.is_server_conflicted("server-endpoint-id"));
        assert!(!reloaded.is_client_blocked("other"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn concurrent_writes_never_corrupt() {
        let path = tmp_path("concurrent");
        let _ = std::fs::remove_file(&path);

        // Two distinct valid snapshots; each writer writes a whole snapshot.
        let mut a = BlockList::load(tmp_path("ca")).unwrap();
        a.add_blocked_client("aaaaaaaa", "a");
        let json_a = a.to_json().unwrap();
        let mut b = BlockList::load(tmp_path("cb")).unwrap();
        b.add_conflicted_server("bbbbbbbb", "b");
        let json_b = b.to_json().unwrap();

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let p = path.clone();
                let json = if i % 2 == 0 { json_a.clone() } else { json_b.clone() };
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        write_atomic(&p, &json).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        // Whatever the last writer was, the file must be a complete, valid
        // snapshot (never a torn/corrupt one) that reloads cleanly.
        let reloaded = BlockList::load(path.clone()).unwrap();
        let ok = reloaded.is_client_blocked("aaaaaaaa") || reloaded.is_server_conflicted("bbbbbbbb");
        assert!(ok, "reloaded blocklist should be one of the valid snapshots");

        // No orphan temp files should be left in the directory.
        let dir = path.parent().unwrap();
        let leftover: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("flextunnel-blocklist-test-concurrent") && n.contains(".tmp"))
            .collect();
        assert!(leftover.is_empty(), "orphan temp files left: {leftover:?}");

        let _ = std::fs::remove_file(&path);
    }
}
