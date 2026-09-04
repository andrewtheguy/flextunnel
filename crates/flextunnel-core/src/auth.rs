//! Public-key authentication for flextunnel client connections.
//!
//! The transcript — sign the client's own ephemeral endpoint id, verify it
//! against the connection's TLS-authenticated `remote_id()` and the
//! authorized-keys file — is the shared [`flexaccess_iroh::auth`] one, and the
//! key format and files are
//! [flexaccess-keys](https://github.com/flexaccessdev/flexaccess-keys). This
//! module owns only what makes it flextunnel's: the domain-separation
//! context, and the authorization decision in the server's handshake.
//!
//! Keypairs authenticate **clients** only. Bridges (a server connecting to
//! another server) and quick-mode clients carry no keypair: their credential is
//! their TLS-authenticated iroh endpoint id, checked against the receiving
//! server's allowlist at the handshake.
//!
//! Generate client keys with `flexaccess-keys generate-auth-key`.

use flexaccess_keys::PublicKey;
use iroh::EndpointId;

pub use flexaccess_iroh::auth::{
    AuthorizedKeys, ClientKey, load_authorized_keys, load_client_key_from_file,
};

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

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

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
