//! Token-based authentication for iroh tunnel connections.
//!
//! Provides pre-shared token authentication for the iroh multi-source server.
//!
//! ## Token Format
//! - Exactly 49 characters
//! - Starts with a 3-char role prefix: `ftc` (client) or `ftb` (bridge — a
//!   server connecting to another server)
//! - Remaining 46 characters are Base64URL (no padding)
//! - Decoded payload is exactly 34 bytes:
//!   - First 32 bytes: random entropy
//!   - Last 2 bytes: CRC16-CCITT-FALSE checksum (big-endian) of the 32 random bytes
//!
//! All roles share this format but use distinct prefixes so a credential for
//! one role can never authenticate as another — the server validates each
//! against the prefix for the connecting peer's role.
//!
//! Generate client tokens with `flextunnel generate-auth-token`, bridge tokens
//! with `flextunnel generate-bridge-token`.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use std::collections::HashSet;
use std::path::Path;

/// Required length for authentication tokens.
pub const TOKEN_LENGTH: usize = 49;

/// Required prefix for client tokens.
pub const CLIENT_TOKEN_PREFIX: &str = "ftc";

/// Required prefix for bridge tokens (server-to-server).
pub const BRIDGE_TOKEN_PREFIX: &str = "ftb";

/// Number of random bytes in token payload.
const RANDOM_BYTES_LEN: usize = 32;

/// Number of checksum bytes in token payload.
const CHECKSUM_BYTES_LEN: usize = 2;

/// Number of decoded bytes in token payload.
const TOKEN_PAYLOAD_LEN: usize = RANDOM_BYTES_LEN + CHECKSUM_BYTES_LEN;

/// Compute CRC16-CCITT-FALSE.
///
/// Parameters:
/// - Poly: 0x1021
/// - Init: 0xFFFF
/// - RefIn: false
/// - RefOut: false
/// - XorOut: 0x0000
fn crc16_ccitt_false(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;

    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }

    crc
}

/// Generate a new client authentication token (prefix `ftc`).
pub fn generate_client_token() -> String {
    generate_token_with_prefix(CLIENT_TOKEN_PREFIX)
}

/// Generate a new bridge authentication token (prefix `ftb`).
pub fn generate_bridge_token() -> String {
    generate_token_with_prefix(BRIDGE_TOKEN_PREFIX)
}

/// Generate a new authentication token with the given 3-char role prefix.
///
/// Format: `<prefix>` + base64url_no_pad(32 random bytes + 2-byte CRC16) = 49
/// characters total.
pub fn generate_token_with_prefix(prefix: &str) -> String {
    let mut random = [0u8; RANDOM_BYTES_LEN];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut random);

    let checksum = crc16_ccitt_false(&random).to_be_bytes();
    let mut payload = [0u8; TOKEN_PAYLOAD_LEN];
    payload[..RANDOM_BYTES_LEN].copy_from_slice(&random);
    payload[RANDOM_BYTES_LEN..].copy_from_slice(&checksum);

    format!("{}{}", prefix, URL_SAFE_NO_PAD.encode(payload))
}

/// Validate a client token (prefix `ftc`).
pub fn validate_client_token(token: &str) -> Result<()> {
    validate_token_with_prefix(token, CLIENT_TOKEN_PREFIX)
}

/// Validate a bridge token (prefix `ftb`).
pub fn validate_bridge_token(token: &str) -> Result<()> {
    validate_token_with_prefix(token, BRIDGE_TOKEN_PREFIX)
}

/// Validate token format against a specific role prefix.
///
/// Returns Ok(()) if valid, Err with description if invalid.
pub fn validate_token_with_prefix(token: &str, prefix: &str) -> Result<()> {
    // Early ASCII check - all valid tokens are ASCII
    if !token.is_ascii() {
        anyhow::bail!("Token must contain only ASCII characters");
    }

    if token.len() != TOKEN_LENGTH {
        anyhow::bail!(
            "Token must be exactly {} characters, got {} characters",
            TOKEN_LENGTH,
            token.len()
        );
    }

    // Check prefix
    if !token.starts_with(prefix) {
        anyhow::bail!(
            "Token must start with '{}', got '{}'",
            prefix,
            &token[..prefix.len().min(token.len())]
        );
    }

    let encoded_payload = &token[prefix.len()..];
    let payload = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .context("Token payload is not valid base64url without padding")?;

    if payload.len() != TOKEN_PAYLOAD_LEN {
        anyhow::bail!(
            "Token payload must decode to exactly {} bytes, got {} bytes",
            TOKEN_PAYLOAD_LEN,
            payload.len()
        );
    }

    let random = &payload[..RANDOM_BYTES_LEN];
    let checksum = &payload[RANDOM_BYTES_LEN..];
    let expected_checksum = crc16_ccitt_false(random).to_be_bytes();

    if checksum != expected_checksum {
        anyhow::bail!("Token checksum is invalid");
    }

    Ok(())
}

/// Load auth tokens from CLI arguments and/or a file, validating each against
/// the given role `prefix` (`ftc` for clients, `ftb` for bridges).
///
/// # Arguments
/// * `cli_tokens` - Tokens specified via CLI `--auth-tokens` flags
/// * `file` - Optional path to a file containing tokens (one per line)
/// * `prefix` - Required role prefix every token must carry
///
/// # Returns
/// A HashSet of all valid authentication tokens
///
/// # Errors
/// Returns an error if the file cannot be read or any token is invalid
pub fn load_auth_tokens(
    cli_tokens: &[String],
    file: Option<&Path>,
    prefix: &str,
) -> Result<HashSet<String>> {
    let mut tokens = HashSet::new();

    // Load from CLI arguments. Identify a bad token by its position, never by
    // value — the token is a credential and must not leak into logs/output.
    for (idx, token) in cli_tokens.iter().enumerate() {
        let trimmed = token.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            validate_token_with_prefix(trimmed, prefix)
                .with_context(|| format!("Invalid token at CLI argument #{}", idx + 1))?;
            tokens.insert(trimmed.to_string());
        }
    }

    // Load from file if specified
    if let Some(file_path) = file {
        let file_tokens = load_auth_tokens_from_file(file_path, prefix)?;
        tokens.extend(file_tokens);
    }

    Ok(tokens)
}

/// Load authentication tokens from a file.
///
/// # File Format
/// - One token per line (`v` + 46 Base64URL chars, no padding)
/// - Lines starting with `#` are treated as comments
/// - Empty lines are ignored
/// - Inline comments (after token) are supported with `#`
///
/// # Example file:
/// ```text
/// # Authentication tokens (generate with: flextunnel generate-auth-token)
/// vmfNFxTPDKB3jsM1Q8kzAvZnQHbmJ1W49Rk8i1S2Jzrze9Q
/// vh9SwOUD1nHkQpl4Gf0fQrVrRIt6QctNfPzIlcwkPhzv0ig
/// ```
pub fn load_auth_tokens_from_file(path: &Path, prefix: &str) -> Result<HashSet<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read auth tokens file: {}", path.display()))?;

    let mut tokens = HashSet::new();

    for (line_num, token) in meaningful_token_lines(&content) {
        // Locate by file:line only; never echo the token value (a credential).
        validate_token_with_prefix(token, prefix)
            .with_context(|| format!("Invalid token at {}:{}", path.display(), line_num))?;
        tokens.insert(token.to_string());
    }

    Ok(tokens)
}

/// Yield the meaningful `(line_num, token)` pairs from a token file's contents.
///
/// Line numbers are 1-based. Empty lines and `#` comment lines are skipped,
/// inline `#` comments are stripped, and surrounding whitespace is trimmed;
/// lines that are empty after stripping are skipped. Shared by all token-file
/// loaders so their parsing stays identical.
fn meaningful_token_lines(content: &str) -> impl Iterator<Item = (usize, &str)> {
    content.lines().enumerate().filter_map(|(i, line)| {
        let line = line.trim();
        // Skip empty lines and comment lines.
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        // Handle inline comments: take only the part before #.
        let token = line.split('#').next().unwrap_or(line).trim();
        if token.is_empty() {
            None
        } else {
            Some((i + 1, token))
        }
    })
}

/// Load a single auth token from a file.
///
/// # File Format
/// - First non-empty, non-comment line is the token (`v` + 46 Base64URL chars, no padding)
/// - Lines starting with `#` are treated as comments
/// - Empty lines are ignored
/// - Inline comments (after token) are supported with `#`
pub fn load_auth_token_from_file(path: &Path, prefix: &str) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read auth token file: {}", path.display()))?;

    if let Some((line_num, token)) = meaningful_token_lines(&content).next() {
        // Locate by file:line only; never echo the token value (a credential).
        validate_token_with_prefix(token, prefix)
            .with_context(|| format!("Invalid token at {}:{}", path.display(), line_num))?;
        return Ok(token.to_string());
    }

    anyhow::bail!("No valid token found in file: {}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_test_token(random: [u8; RANDOM_BYTES_LEN]) -> String {
        let checksum = crc16_ccitt_false(&random).to_be_bytes();
        let mut payload = [0u8; TOKEN_PAYLOAD_LEN];
        payload[..RANDOM_BYTES_LEN].copy_from_slice(&random);
        payload[RANDOM_BYTES_LEN..].copy_from_slice(&checksum);
        format!("{}{}", CLIENT_TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(payload))
    }

    fn decode_payload(token: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(&token[CLIENT_TOKEN_PREFIX.len()..])
            .unwrap()
    }

    #[test]
    fn test_crc16_ccitt_false_known_vector() {
        // Standard check value for CRC16-CCITT-FALSE with "123456789".
        assert_eq!(crc16_ccitt_false(b"123456789"), 0x29B1);
    }

    #[test]
    fn test_generate_token_format() {
        let token = generate_client_token();
        assert_eq!(token.len(), TOKEN_LENGTH);
        assert!(token.starts_with(CLIENT_TOKEN_PREFIX));
        assert!(validate_client_token(&token).is_ok());
    }

    #[test]
    fn test_generate_token_uniqueness() {
        let token1 = generate_client_token();
        let token2 = generate_client_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_validate_token_valid() {
        let token = make_test_token([0xAB; RANDOM_BYTES_LEN]);
        assert!(validate_client_token(&token).is_ok());
    }

    #[test]
    fn test_validate_token_too_short() {
        let result = validate_client_token("ftcshort");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("exactly 49 characters")
        );
    }

    #[test]
    fn test_validate_token_too_long() {
        let token = format!("{}{}", CLIENT_TOKEN_PREFIX, "A".repeat(TOKEN_LENGTH));
        let result = validate_client_token(&token);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("exactly 49 characters")
        );
    }

    #[test]
    fn test_validate_token_wrong_prefix() {
        let mut token = generate_client_token().chars().collect::<Vec<_>>();
        token[0] = 'x';
        let token: String = token.into_iter().collect();

        let result = validate_client_token(&token);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must start with 'ftc'")
        );
    }

    #[test]
    fn test_validate_token_invalid_base64url_chars() {
        let token = format!("{}{}", CLIENT_TOKEN_PREFIX, "!".repeat(TOKEN_LENGTH - CLIENT_TOKEN_PREFIX.len()));
        let result = validate_client_token(&token);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("base64url"));
    }

    #[test]
    fn test_validate_token_non_ascii() {
        let result = validate_client_token("ftc🔐notascii");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ASCII"));
    }

    #[test]
    fn test_validate_token_bad_checksum() {
        let mut payload = decode_payload(&generate_client_token());
        payload[RANDOM_BYTES_LEN] ^= 0x01;
        let bad = format!("{}{}", CLIENT_TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(payload));

        let result = validate_client_token(&bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("checksum"));
    }

    #[test]
    fn test_validate_token_rejects_mutated_random_byte() {
        let mut payload = decode_payload(&generate_client_token());
        payload[0] ^= 0x80;
        let bad = format!("{}{}", CLIENT_TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(payload));

        let result = validate_client_token(&bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("checksum"));
    }

    #[test]
    fn test_validate_token_rejects_mutated_checksum_byte() {
        let mut payload = decode_payload(&generate_client_token());
        payload[TOKEN_PAYLOAD_LEN - 1] ^= 0x01;
        let bad = format!("{}{}", CLIENT_TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(payload));

        let result = validate_client_token(&bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("checksum"));
    }

    #[test]
    fn test_load_from_file_with_comments() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# This is a comment").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "  # Another comment with leading space").unwrap();

        let result = load_auth_tokens_from_file(file.path(), CLIENT_TOKEN_PREFIX).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_load_from_file_with_tokens() {
        let token_a = generate_client_token();
        let token_b = generate_client_token();
        let token_c = generate_client_token();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# Auth tokens").unwrap();
        writeln!(file, "{}", token_a).unwrap();
        writeln!(file, "{}  # inline comment", token_b).unwrap();
        writeln!(file, "  {}  ", token_c).unwrap();

        let result = load_auth_tokens_from_file(file.path(), CLIENT_TOKEN_PREFIX).unwrap();
        assert_eq!(result.len(), 3);
        assert!(result.contains(&token_a));
        assert!(result.contains(&token_b));
        assert!(result.contains(&token_c));
    }

    #[test]
    fn test_load_from_file_invalid_token() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "short").unwrap();

        let result = load_auth_tokens_from_file(file.path(), CLIENT_TOKEN_PREFIX);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_single_token_from_file() {
        let token_a = generate_client_token();
        let token_b = generate_client_token();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# My auth token").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "{}  # comment", token_a).unwrap();
        writeln!(file, "{}", token_b).unwrap(); // ignored

        let result = load_auth_token_from_file(file.path(), CLIENT_TOKEN_PREFIX).unwrap();
        assert_eq!(result, token_a);
    }

    #[test]
    fn test_load_single_token_invalid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "bad").unwrap();

        let result = load_auth_token_from_file(file.path(), CLIENT_TOKEN_PREFIX);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_auth_tokens_cli_and_file() {
        let token_a = generate_client_token();
        let token_b = generate_client_token();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", token_a).unwrap();

        let cli_tokens = vec![token_b.clone()];
        let result = load_auth_tokens(&cli_tokens, Some(file.path()), CLIENT_TOKEN_PREFIX).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains(&token_a));
        assert!(result.contains(&token_b));
    }

    #[test]
    fn test_load_auth_tokens_cli_invalid() {
        let cli_tokens = vec!["short".to_string()];
        let result = load_auth_tokens(&cli_tokens, None, CLIENT_TOKEN_PREFIX);
        assert!(result.is_err());
    }

    #[test]
    fn test_bridge_token_format_and_prefix_isolation() {
        // Bridge tokens are well-formed with the `ftb` prefix...
        let bridge = generate_bridge_token();
        assert_eq!(bridge.len(), TOKEN_LENGTH);
        assert!(bridge.starts_with(BRIDGE_TOKEN_PREFIX));
        assert!(validate_bridge_token(&bridge).is_ok());

        // ...and the two pools are mutually exclusive: a bridge token is not a
        // valid client token, and a client token is not a valid bridge token.
        assert!(validate_client_token(&bridge).is_err());
        assert!(validate_bridge_token(&generate_client_token()).is_err());
    }

    #[test]
    fn test_load_bridge_tokens_rejects_client_prefix() {
        // A client token in a bridge-token file must fail prefix validation.
        let client = generate_client_token();
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", client).unwrap();
        assert!(load_auth_tokens_from_file(file.path(), BRIDGE_TOKEN_PREFIX).is_err());
    }
}
