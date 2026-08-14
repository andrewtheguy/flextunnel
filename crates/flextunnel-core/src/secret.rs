//! Secret key generation and management commands (iroh).

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use iroh::SecretKey;
use log::info;
use std::path::{Path, PathBuf};

use crate::transport::endpoint::{load_secret, load_secret_from_string, secret_to_endpoint_id};

fn write_secret_to_output(
    output: &PathBuf,
    secret_content: &str,
    public_info: &str,
    force: bool,
    secret_label: &str,
) -> Result<()> {
    if output.as_os_str() == std::ffi::OsStr::new("-") {
        println!("{}", secret_content);
        eprintln!("{}", public_info);
        return Ok(());
    }

    if output.exists() && !force {
        anyhow::bail!(
            "File already exists: {}. Use --force to overwrite.",
            output.display()
        );
    }

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).context("Failed to create parent directory")?;
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut options = std::fs::OpenOptions::new();
        options.write(true).mode(0o600);
        if force {
            // Overwrite an existing file in place.
            options.create(true).truncate(true);
        } else {
            // Atomically refuse to overwrite, closing the TOCTOU window between
            // the `output.exists()` check above and this open.
            options.create_new(true);
        }
        let mut file = options
            .open(output)
            .context("Failed to open secret key file")?;

        // `.mode(0o600)` only takes effect when the file is created; on a
        // force-overwrite of a pre-existing file its old permissions persist,
        // so tighten the open descriptor explicitly before writing the secret.
        if force {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .context("Failed to set secret key file permissions")?;
        }

        file.write_all(secret_content.as_bytes())
            .context("Failed to write secret key file")?;
    }

    #[cfg(not(unix))]
    {
        use std::io::Write;

        // Mirror the Unix path: when not forcing, refuse to overwrite atomically
        // via `create_new` (closing the TOCTOU window after the `exists()` check)
        // instead of `std::fs::write`, which would truncate an existing file.
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        if force {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        let mut file = options
            .open(output)
            .context("Failed to open secret key file")?;
        file.write_all(secret_content.as_bytes())
            .context("Failed to write secret key file")?;
    }

    info!("{} saved to: {}", secret_label, output.display());
    println!("{}", public_info);

    Ok(())
}

/// Generate a new secret key file (base64 encoded) and output the EndpointId to
/// stdout. With `json`, everything printed to stdout is a single JSON object
/// (for QA automation): the endpoint id plus either the written file path or,
/// for `-`, the secret itself.
pub fn generate_secret(output: PathBuf, force: bool, json: bool) -> Result<()> {
    let secret = SecretKey::generate();
    let secret_base64 = BASE64.encode(secret.to_bytes());
    let endpoint_id = secret_to_endpoint_id(&secret);
    if json && output.as_os_str() == std::ffi::OsStr::new("-") {
        println!(
            "{}",
            serde_json::json!({
                "endpoint_id": endpoint_id.to_string(),
                "secret": secret_base64,
            })
        );
        return Ok(());
    }
    let public_info = if json {
        serde_json::json!({
            "endpoint_id": endpoint_id.to_string(),
            "secret_file": output.display().to_string(),
        })
        .to_string()
    } else {
        format!("EndpointId: {}", endpoint_id)
    };
    write_secret_to_output(&output, &secret_base64, &public_info, force, "Secret key")
}

/// Generate a new client authentication keypair (see [`crate::auth`]) as an
/// age-style key file, printing the public key to share with the server
/// operator. With `json`, everything printed to stdout is a single JSON object
/// (for QA automation): created timestamp and public key, plus either the
/// written file path or, for `-`, the secret key itself.
pub fn generate_client_key(output: PathBuf, force: bool, json: bool) -> Result<()> {
    let key = crate::auth::ClientKey::generate();
    let created = crate::auth::utc_timestamp();
    let contents = key.to_key_file(&created);
    if output.as_os_str() == std::ffi::OsStr::new("-") {
        // Print the whole key file (comments + secret) to stdout like
        // age-keygen, or one JSON object carrying the same fields.
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "created": created,
                    "public_key": key.public_str(),
                    "secret_key": key.secret_str(),
                })
            );
        } else {
            print!("{contents}");
            eprintln!("Public key: {}", key.public_str());
        }
        return Ok(());
    }
    let public_info = if json {
        serde_json::json!({
            "created": created,
            "public_key": key.public_str(),
            "secret_file": output.display().to_string(),
        })
        .to_string()
    } else {
        format!("Public key: {}", key.public_str())
    };
    write_secret_to_output(&output, &contents, &public_info, force, "Client key")
}

/// Generate a fresh ephemeral server identity, returning its base64 encoding
/// (suitable for `ServerConfig.secret`) and derived `EndpointId`. Used by
/// `server start --quick`, which never persists the key to disk.
pub fn generate_ephemeral_secret() -> (String, crate::iroh::EndpointId) {
    let secret = SecretKey::generate();
    let endpoint_id = secret_to_endpoint_id(&secret);
    (BASE64.encode(secret.to_bytes()), endpoint_id)
}

/// Resolve a server secret key from an inline base64 string and/or a key file,
/// exactly one of which must be provided. Shared by `flextunnel server start` and
/// `flextunnel show-server-id` so both accept the same `secret`/`secret_file`
/// config.
pub fn resolve_secret_key(secret: Option<&str>, secret_file: Option<&Path>) -> Result<SecretKey> {
    match (secret, secret_file) {
        (Some(_), Some(_)) => anyhow::bail!("Provide only one of secret or secret_file, not both"),
        (Some(s), None) => load_secret_from_string(s).context("Invalid inline secret key"),
        (None, Some(path)) => load_secret(path).context("Failed to load secret key"),
        (None, None) => anyhow::bail!(
            "No secret key configured.\n\
             Generate one with: flextunnel generate-server-key -o <FILE>\n\
             Then pass --secret-file <FILE> or set secret_file/secret in the config."
        ),
    }
}

/// Show the EndpointId for a server secret resolved from `secret`/`secret_file`.
/// With `json`, prints a single JSON object instead (for QA automation).
pub fn show_id(secret: Option<&str>, secret_file: Option<&Path>, json: bool) -> Result<()> {
    let secret = resolve_secret_key(secret, secret_file)?;
    let endpoint_id = secret_to_endpoint_id(&secret);
    if json {
        println!(
            "{}",
            serde_json::json!({ "endpoint_id": endpoint_id.to_string() })
        );
    } else {
        println!("{}", endpoint_id);
    }
    Ok(())
}
