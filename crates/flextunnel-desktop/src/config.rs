//! Profile persistence. The non-secret profile data (name, server id, ports,
//! forwards) lives in a plaintext `profiles.json` under the local data dir —
//! same treatment as the iOS app's `forwards.json`. Auth tokens are the only
//! secret and are stored one keychain entry per profile (macOS Keychain /
//! Windows Credential Manager, account = profile id), which keeps every blob
//! tiny — Windows caps credential blobs at ~2.5 KB.
//!
//! Development escape hatch: setting `FLEXTUNNEL_DEV_CONFIG` swaps all of the
//! above for a single plaintext JSON file with the tokens inline, so a rebuild
//! loop doesn't hit the macOS keychain access prompt on every unsigned binary.
//! Never set it for a real install — the auth tokens are stored unencrypted.

use flextunnel_core::forwards::PortForward;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub const DEFAULT_SOCKS_PORT: u16 = 1080;
/// Suggested HTTP proxy port for the profile form. Deliberately high — 8080
/// is taken by half the dev servers in the world (mirrors the iOS FFI's
/// choice of 18080 for its SOCKS default).
pub const DEFAULT_HTTP_PORT: u16 = 18080;

const KEYCHAIN_SERVICE: &str = "flextunnel-desktop";

/// Set this (to `1`/`true` for the default dev path, or to an explicit file
/// path) to store profiles as plaintext JSON instead of the system keychain.
/// Development only — see the module docs.
const DEV_CONFIG_ENV: &str = "FLEXTUNNEL_DEV_CONFIG";

/// Chosen once by `init_store`; `File` when the dev env var is set, otherwise
/// the platform keychain via `keyring-core` for tokens + `profiles.json` for
/// the rest.
enum Backend {
    Keychain,
    File(PathBuf),
}

static BACKEND: OnceLock<Backend> = OnceLock::new();

/// One connection profile — the desktop equivalent of a `client.toml`. Each
/// active profile runs its own tunnel session with optional local proxy
/// front-ends and its own server-direct port forwards.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub server_node_id: String,
    /// The one secret. Never serialized here: in keychain mode it lives in a
    /// per-profile keychain entry; the dev file backend re-adds it via
    /// [`StoredProfile`].
    #[serde(skip)]
    pub auth_token: String,
    /// Local SOCKS5 proxy port; `None` leaves that front-end disabled.
    #[serde(default)]
    pub socks_port: Option<u16>,
    /// Local HTTP proxy port; `None` leaves the HTTP front-end disabled.
    #[serde(default)]
    pub http_port: Option<u16>,
    #[serde(default)]
    pub relay_urls: Vec<String>,
    /// Shared bearer token sent to every custom relay (custom relays only).
    /// TODO(keychain): stored in the profile for now; move to the keychain when
    /// all secrets migrate there (see the iOS roadmap note).
    #[serde(default)]
    pub relay_auth_token: Option<String>,
    #[serde(default)]
    pub forwards: Vec<PortForward>,
}

impl Profile {
    pub fn new_id() -> String {
        format!("{:016x}", rand::random::<u64>())
    }

    /// A well-formed profile name: 1-64 characters, words separated by single
    /// spaces — no leading/trailing spaces, no consecutive spaces, no other
    /// whitespace. The form normalizes into this shape; only a hand-edited
    /// file can violate it.
    pub fn is_valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.chars().count() <= 64
            && !name.starts_with(' ')
            && !name.ends_with(' ')
            && !name.contains("  ")
            && !name.chars().any(|c| c.is_whitespace() && c != ' ')
    }

    /// Whether the profile can be connected: a missing token happens when its
    /// keychain entry was lost (the user re-enters it in the edit form).
    pub fn is_ready(&self) -> bool {
        !self.server_node_id.is_empty() && !self.auth_token.is_empty()
    }
}

/// Serialization wrapper for the dev file backend only: the token rides along
/// inline (plaintext, development only) since there is no keychain to hold it.
#[derive(Serialize, Deserialize)]
struct StoredProfile {
    #[serde(default)]
    auth_token: String,
    #[serde(flatten)]
    profile: Profile,
}

/// Path to the plaintext dev profiles file when `FLEXTUNNEL_DEV_CONFIG` is
/// set, else `None`. `1`/`true` picks a default location under the local data
/// dir; any other value is treated as an explicit file path.
fn dev_config_path() -> Option<PathBuf> {
    let val = std::env::var(DEV_CONFIG_ENV).ok()?;
    match val.as_str() {
        "" => None,
        "1" | "true" => {
            dirs::data_local_dir().map(|d| d.join("flextunnel").join("dev-profiles.json"))
        }
        path => Some(PathBuf::from(path)),
    }
}

fn profiles_path() -> Result<PathBuf> {
    dirs::data_local_dir()
        .map(|d| d.join("flextunnel").join("profiles.json"))
        .ok_or_else(|| anyhow::anyhow!("no local data directory to store profiles in"))
}

/// Choose the storage backend. Must run before any load/save; returns false
/// when no store is available.
pub fn init_store() -> bool {
    if let Some(path) = dev_config_path() {
        log::warn!(
            "{DEV_CONFIG_ENV} set: storing profiles (tokens included) UNENCRYPTED at {} \
             (development only)",
            path.display()
        );
        let _ = BACKEND.set(Backend::File(path));
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        match apple_native_keyring_store::keychain::Store::new() {
            Ok(store) => {
                keyring_core::set_default_store(store);
                let _ = BACKEND.set(Backend::Keychain);
                return true;
            }
            Err(e) => log::error!("Failed to open the macOS keychain store: {e}"),
        }
    }
    #[cfg(windows)]
    {
        match windows_native_keyring_store::Store::new() {
            Ok(store) => {
                keyring_core::set_default_store(store);
                let _ = BACKEND.set(Backend::Keychain);
                return true;
            }
            Err(e) => log::error!("Failed to open the Windows credential store: {e}"),
        }
    }
    false
}

fn token_entry(profile_id: &str) -> Result<keyring_core::Entry> {
    keyring_core::Entry::new(KEYCHAIN_SERVICE, profile_id)
        .context("Failed to open keychain entry")
}

/// Drop structurally invalid entries from a (possibly hand-edited) profiles
/// file, keeping the first occurrence of duplicates: duplicate profile ids
/// break the session/snapshot keying, malformed or duplicate names break
/// everything keyed by name (session thread names / log attribution, tray
/// submenus), and duplicate server node ids mean two profiles for one server.
/// The form rejects all of these; this is the backstop.
fn drop_invalid(profiles: Vec<Profile>) -> Vec<Profile> {
    let mut ids = std::collections::HashSet::new();
    let mut names = std::collections::HashSet::new();
    let mut servers = std::collections::HashSet::new();
    profiles
        .into_iter()
        .filter(|p| {
            if !ids.insert(p.id.clone()) {
                log::error!("Ignoring profile \"{}\": duplicate profile id {}", p.name, p.id);
                return false;
            }
            if !Profile::is_valid_name(&p.name) {
                log::error!(
                    "Ignoring profile {}: invalid name {:?} (1-64 chars, single spaces \
                     between words only)",
                    p.id,
                    p.name
                );
                return false;
            }
            if !names.insert(p.name.clone()) {
                log::error!("Ignoring a profile: duplicate profile name \"{}\"", p.name);
                return false;
            }
            if !servers.insert(p.server_node_id.clone()) {
                log::error!(
                    "Ignoring profile \"{}\": another profile already uses its server node id",
                    p.name
                );
                return false;
            }
            true
        })
        .collect()
}

/// Load all profiles; an empty list when nothing has been saved yet. In
/// keychain mode each profile's token is filled from its keychain entry — a
/// missing entry loads as an empty token with a warning instead of failing.
/// Entries duplicating another's profile id or server node id are ignored.
pub fn load_profiles() -> Result<Vec<Profile>> {
    match BACKEND.get() {
        Some(Backend::File(path)) => Ok(drop_invalid(load_dev_file(path)?)),
        _ => {
            let profiles: Vec<Profile> = match read_json(&profiles_path()?)? {
                Some(profiles) => profiles,
                None => return Ok(Vec::new()),
            };
            let mut profiles = drop_invalid(profiles);
            for profile in &mut profiles {
                match token_entry(&profile.id)?.get_password() {
                    Ok(token) => profile.auth_token = token,
                    Err(keyring_core::Error::NoEntry) => log::warn!(
                        "No keychain token for profile \"{}\"; it must be re-entered",
                        profile.name
                    ),
                    Err(e) => return Err(e).context("Failed to read a token from the keychain"),
                }
            }
            Ok(profiles)
        }
    }
}

/// Persist the profile list (non-secret data only in keychain mode — tokens
/// are written separately by [`save_profile_secret`], so routine saves after
/// a forward toggle never touch the keychain).
pub fn save_profiles(profiles: &[Profile]) -> Result<()> {
    match BACKEND.get() {
        Some(Backend::File(path)) => save_dev_file(path, profiles),
        _ => write_json(&profiles_path()?, &profiles),
    }
}

/// Field holding the second secret. Unlike `auth_token` it has to serialize
/// (it lives in `profiles.json`), so export/import strip it by hand instead.
const RELAY_TOKEN_FIELD: &str = "relay_auth_token";

/// Export all profiles to a user-chosen file. Non-secrets only, whatever the
/// backend: `Profile`'s serialization always skips the auth token, and the
/// relay auth token is removed here. Profile and forward ids are stripped too
/// — they are app-local keys that the import regenerates, not part of the
/// portable data.
pub fn export_profiles(path: &Path, profiles: &[Profile]) -> Result<()> {
    let mut values = serde_json::to_value(profiles)?;
    for entry in values.as_array_mut().into_iter().flatten() {
        if let Some(profile) = entry.as_object_mut() {
            profile.remove("id");
            profile.remove(RELAY_TOKEN_FIELD);
            for forward in forwards_of(profile) {
                forward.remove("id");
            }
        }
    }
    write_json(path, &values)
}

/// Read an export file back, applying the same structural validation as a
/// load (malformed names and in-file duplicates are dropped with logs). The
/// caller merges the result into the current profiles and assigns final ids;
/// missing ids (the normal export shape) get placeholders here so the entries
/// deserialize. Neither secret is imported: the auth token is never in the
/// file, and any relay auth token in a hand-written one is dropped, so
/// imported entries come back with both empty.
pub fn import_profiles(path: &Path) -> Result<Vec<Profile>> {
    let mut values: serde_json::Value = read_json(path)?
        .ok_or_else(|| anyhow::anyhow!("{} does not exist", path.display()))?;
    for entry in values.as_array_mut().into_iter().flatten() {
        if let Some(profile) = entry.as_object_mut() {
            profile
                .entry("id")
                .or_insert_with(|| Profile::new_id().into());
            profile.remove(RELAY_TOKEN_FIELD);
            for forward in forwards_of(profile) {
                forward
                    .entry("id")
                    .or_insert_with(|| PortForward::new_id().into());
            }
        }
    }
    let profiles: Vec<Profile> = serde_json::from_value(values)
        .with_context(|| format!("Failed to parse {}", path.display()))?;
    Ok(drop_invalid(profiles))
}

/// The mutable forward objects of a profile JSON object (empty when absent).
fn forwards_of(
    profile: &mut serde_json::Map<String, serde_json::Value>,
) -> impl Iterator<Item = &mut serde_json::Map<String, serde_json::Value>> {
    profile
        .get_mut("forwards")
        .and_then(|f| f.as_array_mut())
        .into_iter()
        .flatten()
        .filter_map(|f| f.as_object_mut())
}

/// Store one profile's token. Called only when the token itself changes (the
/// profile form is saved); a no-op in dev file mode where `save_profiles`
/// already wrote it inline.
pub fn save_profile_secret(profile_id: &str, token: &str) -> Result<()> {
    match BACKEND.get() {
        Some(Backend::File(_)) => Ok(()),
        _ => token_entry(profile_id)?
            .set_password(token)
            .context("Failed to write the token to the keychain"),
    }
}

/// Remove a deleted profile's keychain entry (no-op in dev file mode). Best
/// effort: a stale entry is harmless.
pub fn delete_profile_secret(profile_id: &str) {
    if let Some(Backend::File(_)) = BACKEND.get() {
        return;
    }
    match token_entry(profile_id) {
        Ok(entry) => match entry.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => {}
            Err(e) => log::warn!("Failed to delete the keychain token: {e}"),
        },
        Err(e) => log::warn!("{e:#}"),
    }
}

fn load_dev_file(path: &Path) -> Result<Vec<Profile>> {
    let stored: Vec<StoredProfile> = match read_json(path)? {
        Some(stored) => stored,
        None => return Ok(Vec::new()),
    };
    Ok(stored
        .into_iter()
        .map(|s| Profile {
            auth_token: s.auth_token,
            ..s.profile
        })
        .collect())
}

fn save_dev_file(path: &Path, profiles: &[Profile]) -> Result<()> {
    let stored: Vec<StoredProfile> = profiles
        .iter()
        .map(|p| StoredProfile {
            auth_token: p.auth_token.clone(),
            profile: p.clone(),
        })
        .collect();
    write_json(path, &stored)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match std::fs::read(path) {
        Ok(raw) => Ok(Some(
            serde_json::from_slice(&raw)
                .with_context(|| format!("Failed to parse {}", path.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("Failed to read {}", path.display())),
    }
}

/// Write via a temp file + rename so a crash mid-write can't truncate the file.
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("profiles path has no parent directory"))?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create {}", dir.display()))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("Failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("Failed to persist {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Profile {
        Profile {
            id: "00000000deadbeef".into(),
            name: "prod".into(),
            server_node_id: "node".into(),
            // Distinctive sentinel so the leak-check assertions match the token
            // *value* and don't collide with field names like `relay_auth_token`.
            auth_token: "ftc-secret-authtok".into(),
            socks_port: Some(1085),
            http_port: Some(8081),
            relay_urls: vec!["https://relay.example".into()],
            relay_auth_token: Some("ftc-secret-relaypsk".into()),
            forwards: vec![PortForward {
                id: "aaaa".into(),
                label: "db".into(),
                local_port: 5432,
                remote_host: "db.internal".into(),
                remote_port: 5432,
                enabled: true,
            }],
        }
    }

    #[test]
    fn optional_fields_default_when_absent() {
        let p: Profile = serde_json::from_str(
            r#"{"id":"1","name":"n","server_node_id":"abc"}"#,
        )
        .unwrap();
        assert_eq!(p.socks_port, None);
        assert_eq!(p.http_port, None);
        assert!(p.relay_urls.is_empty());
        assert!(p.forwards.is_empty());
        assert!(p.auth_token.is_empty());
    }

    #[test]
    fn token_never_serializes_in_profile() {
        let json = serde_json::to_string(&profile()).unwrap();
        assert!(!json.contains("ftc-secret-authtok"), "token leaked: {json}");
        // `enabled` is runtime-only on forwards and must not leak either.
        assert!(!json.contains("enabled"), "enabled leaked: {json}");
        // The relay token is a secret too, but it has no keychain home yet, so
        // it must stay in this serialization (`profiles.json`). Export/import
        // strip it explicitly — see `export_profiles`.
        assert!(
            json.contains("ftc-secret-relaypsk"),
            "relay token must persist in profiles.json: {json}"
        );
    }

    #[test]
    fn duplicate_ids_and_servers_are_dropped() {
        let a = profile();
        let mut same_server = profile();
        same_server.id = "b".into();
        same_server.name = "b".into();
        let mut same_id = profile();
        same_id.name = "c".into();
        same_id.server_node_id = "other".into();
        let mut same_name = profile();
        same_name.id = "n".into();
        same_name.server_node_id = "elsewhere".into();
        let mut bad_name = profile();
        bad_name.id = "w".into();
        bad_name.name = " padded ".into();
        bad_name.server_node_id = "padded-server".into();
        let mut unique = profile();
        unique.id = "d".into();
        unique.name = "d".into();
        unique.server_node_id = "unique".into();

        let kept = drop_invalid(vec![
            a.clone(),
            same_server,
            same_id,
            same_name,
            bad_name,
            unique.clone(),
        ]);
        assert_eq!(kept, vec![a, unique]);
    }

    #[test]
    fn export_strips_ids_and_import_regenerates_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");

        export_profiles(&path, &[profile()]).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("\"id\""), "ids leaked into the export: {raw}");
        assert!(
            !raw.contains("ftc-secret-authtok"),
            "token leaked into the export: {raw}"
        );
        assert!(
            !raw.contains("ftc-secret-relaypsk") && !raw.contains("relay_auth_token"),
            "relay auth token leaked into the export: {raw}"
        );
        // The non-secret relay setting it pairs with still travels.
        assert!(raw.contains("https://relay.example"), "relay urls dropped: {raw}");

        let imported = import_profiles(&path).unwrap();
        assert_eq!(imported.len(), 1);
        let p = &imported[0];
        assert!(!p.id.is_empty(), "placeholder profile id assigned");
        assert!(p.auth_token.is_empty());
        assert_eq!(p.relay_auth_token, None);
        assert_eq!(p.relay_urls, profile().relay_urls);
        assert_eq!(p.name, profile().name);
        assert_eq!(p.socks_port, profile().socks_port);
        assert_eq!(p.forwards.len(), 1);
        assert!(!p.forwards[0].id.is_empty(), "placeholder forward id assigned");
        assert_eq!(p.forwards[0].local_port, profile().forwards[0].local_port);
    }

    /// Older exports (and hand-written files) can carry the relay token; it is
    /// dropped rather than trusted, same as if it had never been written.
    #[test]
    fn import_drops_a_relay_token_present_in_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");
        std::fs::write(
            &path,
            r#"[{"name":"prod","server_node_id":"node",
                 "relay_urls":["https://relay.example"],
                 "relay_auth_token":"ftc-secret-relaypsk"}]"#,
        )
        .unwrap();

        let imported = import_profiles(&path).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].relay_auth_token, None);
        assert_eq!(imported[0].relay_urls, vec!["https://relay.example"]);
    }

    #[test]
    fn name_format_rules() {
        assert!(Profile::is_valid_name("prod"));
        assert!(Profile::is_valid_name("staging aws kube"));

        assert!(!Profile::is_valid_name(""));
        assert!(!Profile::is_valid_name(" prod"));
        assert!(!Profile::is_valid_name("prod "));
        assert!(!Profile::is_valid_name("staging  aws"));
        assert!(!Profile::is_valid_name("staging\taws"));
        assert!(!Profile::is_valid_name("staging\naws"));
        assert!(!Profile::is_valid_name(&"a".repeat(65)));
    }

    #[test]
    fn dev_file_roundtrips_with_tokens_and_missing_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("dev-profiles.json");

        assert!(load_dev_file(&path).unwrap().is_empty());

        let mut profiles = vec![profile()];
        save_dev_file(&path, &profiles).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("\"auth_token\": \"ftc-secret-authtok\""),
            "token missing: {raw}"
        );

        // Forward `enabled` is runtime-only: comes back off.
        profiles[0].forwards[0].enabled = false;
        assert_eq!(load_dev_file(&path).unwrap(), profiles);
    }
}
