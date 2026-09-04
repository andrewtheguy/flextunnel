//! Public-key authentication for flextunnel client connections.
//!
//! The transcript — sign the client's own ephemeral endpoint id, verify it
//! against the connection's TLS-authenticated `remote_id()` and the
//! authorized-keys file — is the shared [`flexaccess_iroh::auth`] one, and the
//! key format and files are
//! [flexaccess-keys](https://github.com/flexaccessdev/flexaccess-keys). This
//! module owns only what makes it flextunnel's: the domain-separation
//! context, the key-file loaders, and the authorization decision in the
//! server's handshake.
//!
//! Keypairs authenticate **clients** only. Bridges (a server connecting to
//! another server) and quick-mode clients carry no keypair: their credential is
//! their TLS-authenticated iroh endpoint id, checked against the receiving
//! server's allowlist at the handshake.
//!
//! Generate client keys with `flexaccess-keys generate-auth-key`.

use anyhow::Result;
use flexaccess_keys::PublicKey;
use iroh::EndpointId;
use std::path::Path;

pub use flexaccess_iroh::auth::{AuthorizedKeys, ClientKey};

/// Domain-separation context prepended to the signed message, so a flextunnel
/// client-auth signature can never be confused with any other ed25519
/// signature made by the same key — including one made for another FlexAccess
/// application sharing the key format and transcript.
const AUTH_CONTEXT: &[u8] = b"flextunnel-client-auth-v1";

/// Sign the client-auth message binding `endpoint_id` (this client's own
/// ephemeral iroh id) under flextunnel's context, returning the base64url
/// signature.
pub fn sign_endpoint_id(key: &ClientKey, endpoint_id: &EndpointId) -> String {
    key.sign_endpoint_id(AUTH_CONTEXT, endpoint_id)
}

/// Verify a base64url client-auth signature over `endpoint_id` under `public`
/// and flextunnel's context.
pub fn verify_endpoint_id_signature(
    public: &PublicKey,
    endpoint_id: &EndpointId,
    signature_b64: &str,
) -> bool {
    flexaccess_iroh::auth::verify_endpoint_id_signature(
        public,
        AUTH_CONTEXT,
        endpoint_id,
        signature_b64,
    )
}

/// Load a client secret key from a shared-format key file (a bare
/// `ed25519-sec:...` token, or the token preceded by `#` header lines).
pub fn load_client_key_from_file(path: &Path) -> Result<ClientKey> {
    let private = flexaccess_keys::load_private_key(path).map_err(anyhow::Error::from)?;
    Ok(private.into())
}

/// Load the server's authorized client public keys (shared authorized-keys
/// document: one `ed25519-pub:...` per line, optional trailing comment, `#`
/// lines and blank lines ignored).
pub fn load_authorized_keys(path: &Path) -> Result<AuthorizedKeys> {
    flexaccess_keys::load_authorized_keys(path).map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn key_files_load_through_the_shared_format() {
        let key = ClientKey::generate().unwrap();
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# Public key: {} alice\n{}", key.public_str(), key.secret_str()).unwrap();
        assert_eq!(
            load_client_key_from_file(file.path()).unwrap().public_str(),
            key.public_str()
        );

        let mut authorized = NamedTempFile::new().unwrap();
        writeln!(authorized, "# clients\n{} alice laptop", key.public_str()).unwrap();
        let keys = load_authorized_keys(authorized.path()).unwrap();
        assert!(keys.contains(&key.public_key()));
        assert_eq!(keys.comment(&key.public_key()), Some("alice laptop"));

        // A secret key pasted into the authorized-keys file is rejected.
        let mut wrong = NamedTempFile::new().unwrap();
        writeln!(wrong, "{}", key.secret_str()).unwrap();
        assert!(load_authorized_keys(wrong.path()).is_err());
    }

    #[test]
    fn signature_is_bound_to_flextunnel_context() {
        let key = ClientKey::generate().unwrap();
        let id = SecretKey::generate().public();
        let sig = sign_endpoint_id(&key, &id);
        assert!(verify_endpoint_id_signature(&key.public_key(), &id, &sig));

        // The same key and id signed under another application's context
        // (ezvpn shares the key format and transcript) is not a flextunnel
        // credential.
        let foreign = key.sign_endpoint_id(b"ezvpn-client-auth-v1", &id);
        assert!(!verify_endpoint_id_signature(&key.public_key(), &id, &foreign));
    }
}
