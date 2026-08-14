//! Public-key authentication for iroh tunnel connections.
//!
//! Regular clients authenticate with an ed25519 keypair (age-style):
//!
//! ## Key format
//! - Public key: `flextunnelpubv1:` + base64url (no padding) of the 32-byte
//!   ed25519 verifying key. Not a secret — always shown unmasked in UIs.
//! - Secret key: `flextunnelsecretv1:` + base64url (no padding) of the 32-byte
//!   ed25519 secret key.
//!
//! A generated client key file looks like:
//! ```text
//! # created: 2026-08-13T01:02:03Z
//! # public key: flextunnelpubv1:...
//! flextunnelsecretv1:...
//! ```
//!
//! The server keeps its accepted client keys in an ssh-`authorized_keys`-style
//! file: one `flextunnelpubv1:...` per line, an optional free-form comment
//! after the key, `#` lines and blank lines ignored.
//!
//! ## Handshake
//! The client's iroh endpoint id stays ephemeral. In its `Hello` the client
//! sends its public key, its claimed endpoint id, and an ed25519 signature
//! over that endpoint id (domain-separated). The server checks that the
//! claimed id equals the connection's TLS-authenticated `remote_id()`, that
//! the signature verifies under the presented public key, and that the key is
//! on the authorized-keys file — binding the credential to this connection so
//! a captured `Hello` cannot be replayed from another endpoint.
//!
//! Keypairs authenticate **clients** only. Bridges (a server connecting to
//! another server) and quick-mode clients carry no keypair: their credential is
//! their TLS-authenticated iroh endpoint id, checked against the receiving
//! server's allowlist at the handshake.
//!
//! Generate client keys with `flextunnel generate-auth-private-key`.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{EndpointId, PublicKey, SecretKey, Signature};
use std::collections::HashSet;
use std::path::Path;

/// Prefix of an encoded client public key.
pub const PUBLIC_KEY_PREFIX: &str = "flextunnelpubv1:";

/// Prefix of an encoded client secret key.
pub const SECRET_KEY_PREFIX: &str = "flextunnelsecretv1:";

/// Domain-separation context prepended to the signed message, so a client-auth
/// signature can never be confused with any other ed25519 signature made by
/// the same key.
const AUTH_CONTEXT: &[u8] = b"flextunnel-client-auth-v1";

/// A client authentication keypair (ed25519).
#[derive(Clone)]
pub struct ClientKey {
    secret: SecretKey,
}

/// `Debug` shows only the public half — the secret must never leak into
/// logs or error context.
impl std::fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKey")
            .field("public", &self.public_str())
            .finish_non_exhaustive()
    }
}

impl ClientKey {
    /// Generate a fresh random keypair.
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::generate(),
        }
    }

    /// Parse an encoded secret key (`flextunnelsecretv1:...`).
    pub fn from_secret_str(s: &str) -> Result<Self> {
        let encoded = s
            .strip_prefix(SECRET_KEY_PREFIX)
            .with_context(|| format!("Secret key must start with '{SECRET_KEY_PREFIX}'"))?;
        let bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(encoded)
            .context("Secret key is not valid base64url without padding")?
            .try_into()
            .map_err(|v: Vec<u8>| {
                anyhow::anyhow!("Secret key must decode to 32 bytes, got {}", v.len())
            })?;
        Ok(Self {
            secret: SecretKey::from_bytes(&bytes),
        })
    }

    /// The encoded secret key (`flextunnelsecretv1:...`).
    pub fn secret_str(&self) -> String {
        format!(
            "{}{}",
            SECRET_KEY_PREFIX,
            URL_SAFE_NO_PAD.encode(self.secret.to_bytes())
        )
    }

    /// The encoded public key (`flextunnelpubv1:...`).
    pub fn public_str(&self) -> String {
        encode_public_key(&self.secret.public())
    }

    /// The verifying half of this keypair.
    pub fn public_key(&self) -> PublicKey {
        self.secret.public()
    }

    /// Render the age-style key file: created + public-key comments, then the
    /// secret line.
    pub fn to_key_file(&self, created_utc: &str) -> String {
        format!(
            "# created: {}\n# public key: {}\n{}\n",
            created_utc,
            self.public_str(),
            self.secret_str()
        )
    }

    /// Sign the client-auth message binding `endpoint_id` (this client's own
    /// ephemeral iroh id), returning the base64url signature.
    pub fn sign_endpoint_id(&self, endpoint_id: &EndpointId) -> String {
        let sig = self.secret.sign(&auth_message(endpoint_id));
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }
}

/// The signed message: domain-separation context + the raw endpoint-id bytes.
fn auth_message(endpoint_id: &EndpointId) -> Vec<u8> {
    let mut msg = Vec::with_capacity(AUTH_CONTEXT.len() + 32);
    msg.extend_from_slice(AUTH_CONTEXT);
    msg.extend_from_slice(endpoint_id.as_bytes());
    msg
}

/// Encode a public key as `flextunnelpubv1:...`.
pub fn encode_public_key(key: &PublicKey) -> String {
    format!("{}{}", PUBLIC_KEY_PREFIX, URL_SAFE_NO_PAD.encode(key.as_bytes()))
}

/// Parse an encoded public key (`flextunnelpubv1:...`).
pub fn parse_public_key(s: &str) -> Result<PublicKey> {
    let encoded = s
        .strip_prefix(PUBLIC_KEY_PREFIX)
        .with_context(|| format!("Public key must start with '{PUBLIC_KEY_PREFIX}'"))?;
    let bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("Public key is not valid base64url without padding")?
        .try_into()
        .map_err(|v: Vec<u8>| {
            anyhow::anyhow!("Public key must decode to 32 bytes, got {}", v.len())
        })?;
    PublicKey::from_bytes(&bytes).context("Public key is not a valid ed25519 curve point")
}

/// Verify a base64url client-auth signature over `endpoint_id` under `public`.
pub fn verify_endpoint_id_signature(
    public: &PublicKey,
    endpoint_id: &EndpointId,
    signature_b64: &str,
) -> bool {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(signature_b64) else {
        return false;
    };
    let Ok(sig) = Signature::try_from(bytes.as_slice()) else {
        return false;
    };
    public.verify(&auth_message(endpoint_id), &sig).is_ok()
}

/// Load a client secret key from a generated key file: the first non-empty,
/// non-`#` line must be the `flextunnelsecretv1:...` secret.
pub fn load_client_key_from_file(path: &Path) -> Result<ClientKey> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read client key file: {}", path.display()))?;
    if let Some((line_num, line)) = meaningful_lines(&content).next() {
        // Locate by file:line only; never echo the line (a credential).
        return ClientKey::from_secret_str(line)
            .with_context(|| format!("Invalid secret key at {}:{}", path.display(), line_num));
    }
    anyhow::bail!("No secret key found in file: {}", path.display())
}

/// Load the server's authorized client public keys.
///
/// # File format (ssh `authorized_keys` style)
/// - One `flextunnelpubv1:...` key per line; anything after the key (separated
///   by whitespace) is a free-form comment
/// - Lines starting with `#` and empty lines are ignored
///
/// # Example file:
/// ```text
/// # Authorized client keys (generate with: flextunnel generate-auth-private-key)
/// flextunnelpubv1:vGm7hYQz... alice laptop
/// flextunnelpubv1:h9SwOUD1... build server
/// ```
pub fn load_authorized_keys(path: &Path) -> Result<HashSet<PublicKey>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read authorized keys file: {}", path.display()))?;

    let mut keys = HashSet::new();
    for (line_num, line) in meaningful_lines(&content) {
        // The first whitespace-separated field is the key; the rest is comment.
        let key = line.split_whitespace().next().unwrap_or(line);
        let parsed = parse_public_key(key)
            .with_context(|| format!("Invalid public key at {}:{}", path.display(), line_num))?;
        keys.insert(parsed);
    }
    Ok(keys)
}

/// Yield the meaningful `(line_num, line)` pairs of a key file: 1-based line
/// numbers, empty lines and `#` comment lines skipped, surrounding whitespace
/// trimmed. Shared by the key-file loaders (including the iroh secret key
/// loader in `transport::endpoint`) so their parsing stays identical.
pub(crate) fn meaningful_lines(content: &str) -> impl Iterator<Item = (usize, &str)> {
    content.lines().enumerate().filter_map(|(i, line)| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            None
        } else {
            Some((i + 1, line))
        }
    })
}

/// The current time as a `YYYY-MM-DDTHH:MM:SSZ` UTC string, for the
/// `# created:` comment of a generated key file. Implemented over the system
/// clock directly (civil-from-days) to avoid a date-time dependency.
pub fn utc_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_utc_timestamp(secs)
}

fn format_utc_timestamp(epoch_secs: i64) -> String {
    let days = epoch_secs.div_euclid(86_400);
    let rem = epoch_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days-since-epoch → (year, month, day), Howard Hinnant's civil-from-days.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn ephemeral_endpoint_id() -> EndpointId {
        SecretKey::generate().public()
    }

    #[test]
    fn keypair_roundtrip() {
        let key = ClientKey::generate();
        let secret = key.secret_str();
        assert!(secret.starts_with(SECRET_KEY_PREFIX));
        let public = key.public_str();
        assert!(public.starts_with(PUBLIC_KEY_PREFIX));

        let reparsed = ClientKey::from_secret_str(&secret).unwrap();
        assert_eq!(reparsed.public_str(), public);
        assert_eq!(parse_public_key(&public).unwrap(), key.public_key());
    }

    #[test]
    fn secret_str_rejects_bad_inputs() {
        // Wrong prefix (a public key is not a secret key).
        let key = ClientKey::generate();
        assert!(ClientKey::from_secret_str(&key.public_str()).is_err());
        // Bad base64.
        assert!(ClientKey::from_secret_str("flextunnelsecretv1:!!!").is_err());
        // Wrong length.
        let short = format!("{}{}", SECRET_KEY_PREFIX, URL_SAFE_NO_PAD.encode([0u8; 16]));
        assert!(ClientKey::from_secret_str(&short).is_err());
    }

    #[test]
    fn public_key_rejects_bad_inputs() {
        assert!(parse_public_key("flextunnelsecretv1:abc").is_err());
        assert!(parse_public_key("flextunnelpubv1:!!!").is_err());
        let short = format!("{}{}", PUBLIC_KEY_PREFIX, URL_SAFE_NO_PAD.encode([0u8; 8]));
        assert!(parse_public_key(&short).is_err());
    }

    #[test]
    fn key_file_format_and_reload() {
        let key = ClientKey::generate();
        let contents = key.to_key_file("2026-08-13T01:02:03Z");
        let mut lines = contents.lines();
        assert_eq!(lines.next(), Some("# created: 2026-08-13T01:02:03Z"));
        assert_eq!(
            lines.next(),
            Some(format!("# public key: {}", key.public_str()).as_str())
        );
        assert_eq!(lines.next(), Some(key.secret_str().as_str()));
        assert_eq!(lines.next(), None);

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        let loaded = load_client_key_from_file(file.path()).unwrap();
        assert_eq!(loaded.public_str(), key.public_str());
    }

    #[test]
    fn key_file_without_secret_is_rejected() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# only comments here").unwrap();
        assert!(load_client_key_from_file(file.path()).is_err());

        let mut bad = NamedTempFile::new().unwrap();
        writeln!(bad, "not-a-key").unwrap();
        let err = load_client_key_from_file(bad.path()).unwrap_err();
        // Located by line, never echoing the content.
        assert!(err.to_string().contains(":1"), "{err}");
    }

    #[test]
    fn signature_binds_endpoint_id() {
        let key = ClientKey::generate();
        let id = ephemeral_endpoint_id();
        let sig = key.sign_endpoint_id(&id);
        assert!(verify_endpoint_id_signature(&key.public_key(), &id, &sig));

        // A different endpoint id (replay from another endpoint) fails.
        let other_id = ephemeral_endpoint_id();
        assert!(!verify_endpoint_id_signature(&key.public_key(), &other_id, &sig));

        // A different key fails.
        let other_key = ClientKey::generate();
        assert!(!verify_endpoint_id_signature(&other_key.public_key(), &id, &sig));

        // Garbage signatures fail instead of erroring.
        assert!(!verify_endpoint_id_signature(&key.public_key(), &id, "!!!"));
        assert!(!verify_endpoint_id_signature(&key.public_key(), &id, ""));
    }

    #[test]
    fn authorized_keys_parsing() {
        let a = ClientKey::generate();
        let b = ClientKey::generate();
        let c = ClientKey::generate();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# Authorized client keys").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "{}", a.public_str()).unwrap();
        writeln!(file, "{} alice laptop", b.public_str()).unwrap();
        writeln!(file, "  {}   build server  ", c.public_str()).unwrap();

        let keys = load_authorized_keys(file.path()).unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&a.public_key()));
        assert!(keys.contains(&b.public_key()));
        assert!(keys.contains(&c.public_key()));
    }

    #[test]
    fn authorized_keys_comments_only_is_empty() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# This is a comment").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "  # Another comment with leading space").unwrap();
        assert!(load_authorized_keys(file.path()).unwrap().is_empty());
    }

    #[test]
    fn authorized_keys_invalid_key_is_rejected() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# header").unwrap();
        writeln!(file, "flextunnelpubv1:short").unwrap();
        let err = load_authorized_keys(file.path()).unwrap_err();
        assert!(err.to_string().contains(":2"), "{err}");

        // A secret key pasted into the authorized-keys file is rejected too.
        let mut wrong = NamedTempFile::new().unwrap();
        writeln!(wrong, "{}", ClientKey::generate().secret_str()).unwrap();
        assert!(load_authorized_keys(wrong.path()).is_err());
    }

    #[test]
    fn utc_timestamp_formats_known_instants() {
        assert_eq!(format_utc_timestamp(0), "1970-01-01T00:00:00Z");
        // 2026-08-13T04:05:06Z
        assert_eq!(format_utc_timestamp(1_786_593_906), "2026-08-13T04:05:06Z");
        // Leap-year day: 2024-02-29T23:59:59Z
        assert_eq!(format_utc_timestamp(1_709_251_199), "2024-02-29T23:59:59Z");
    }
}
