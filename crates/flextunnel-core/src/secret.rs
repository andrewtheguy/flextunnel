//! Iroh identity key commands (`generate-iroh-key` / `show-iroh-id`).
//!
//! Client auth keypairs are not managed here: generate them with the
//! standalone `flexaccess-keys` CLI (see [`crate::auth`]).

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use iroh::SecretKey;
use log::info;
use std::path::{Path, PathBuf};

use crate::transport::endpoint::{load_secret, secret_to_endpoint_id};

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

/// Generate a new iroh secret key file (commented header + base64 secret, same
/// shape as the auth key file) and output the iroh id (EndpointId) to stdout.
/// With `json`, everything printed to stdout is a single JSON object (for QA
/// automation): created timestamp and iroh id, plus either the written file
/// path or, for `-`, the secret itself.
pub fn generate_iroh_key(output: PathBuf, force: bool, json: bool) -> Result<()> {
    let secret = SecretKey::generate();
    let secret_base64 = BASE64.encode(secret.to_bytes());
    let endpoint_id = secret_to_endpoint_id(&secret);
    let created = flexaccess_keys::rfc3339_utc(std::time::SystemTime::now());
    let contents = format!("# created: {created}\n# public key: {endpoint_id}\n{secret_base64}\n");
    if output.as_os_str() == std::ffi::OsStr::new("-") {
        // Print the whole key file (comments + secret) to stdout, or one JSON
        // object carrying the same fields. No separate EndpointId line — the
        // `# public key:` comment already shows it.
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "created": created,
                    "endpoint_id": endpoint_id.to_string(),
                    "secret": secret_base64,
                })
            );
        } else {
            print!("{contents}");
        }
        return Ok(());
    }
    let public_info = if json {
        serde_json::json!({
            "created": created,
            "endpoint_id": endpoint_id.to_string(),
            "secret_file": output.display().to_string(),
        })
        .to_string()
    } else {
        format!("EndpointId: {}", endpoint_id)
    };
    write_secret_to_output(&output, &contents, &public_info, force, "Iroh key")
}

/// Resolve a server secret key from its key file — the only source for a
/// persistent identity (there is no inline variant; quick mode's ephemeral
/// identity never goes through here). Shared by `flextunnel server start` and
/// `flextunnel show-iroh-id`.
pub fn resolve_secret_key(secret_file: Option<&Path>) -> Result<SecretKey> {
    match secret_file {
        Some(path) => load_secret(path).context("Failed to load secret key"),
        None => anyhow::bail!(
            "No secret key configured.\n\
             Generate one with: flextunnel generate-iroh-key -o <FILE>\n\
             Then pass --secret-file <FILE> or set secret_file in the config."
        ),
    }
}

/// Show the iroh id (EndpointId) for a server secret key file. With `json`,
/// prints a single JSON object instead (for QA automation).
pub fn show_iroh_id(secret_file: Option<&Path>, json: bool) -> Result<()> {
    let secret = resolve_secret_key(secret_file)?;
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
