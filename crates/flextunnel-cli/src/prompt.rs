//! Interactive prompts for quick mode (`client start --quick` and
//! `server start --quick`), used when the user opts into entering connection
//! details on a terminal. Fills only the values not already supplied on the
//! command line; nothing is persisted.

use anyhow::{Context, Result};
use std::io::{self, Write};

use flextunnel_core::config::ClientConfig;
use flextunnel_core::iroh::EndpointId;

/// Prompt (on the terminal) for any client values still missing from `cli`,
/// mutating it in place. Never writes a config file — the collected values live
/// only for this session. No auth keypair is involved: the quick client's
/// credential is its endpoint id, entered on the quick server.
pub fn fill_client_config(cli: &mut ClientConfig) -> Result<()> {
    // EndpointId of the server to connect to (printed by `server start --quick`).
    if cli.server_node_id.is_none() {
        cli.server_node_id = Some(
            prompt_endpoint_id("Server EndpointId (shown by `flextunnel server start --quick`)")?
                .to_string(),
        );
    }

    // Optional loopback proxy listeners; blank leaves them disabled.
    if cli.socks_port.is_none() {
        cli.socks_port = prompt_optional_port("SOCKS5 port (blank = disabled)")?;
    }
    if cli.http_port.is_none() {
        cli.http_port = prompt_optional_port("HTTP proxy port (blank = disabled)")?;
    }

    Ok(())
}

/// Prompt for an `EndpointId` under `label`, re-asking until it parses. Shared
/// by the quick client (the server's id) and the quick server (the client's id
/// to allowlist) — ids are public, so no masking is needed.
pub fn prompt_endpoint_id(label: &str) -> Result<EndpointId> {
    loop {
        print!("{label}: ");
        io::stdout().flush().context("Failed to write prompt")?;
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .context("Failed to read input")?;
        let value = line.trim();
        if value.is_empty() {
            eprintln!("A value is required.");
            continue;
        }
        match value.parse::<EndpointId>() {
            Ok(id) => return Ok(id),
            Err(err) => eprintln!("Invalid EndpointId: {err}"),
        }
    }
}

/// Prompt for an optional `u16` port; a blank line means "disabled" (`None`).
fn prompt_optional_port(label: &str) -> Result<Option<u16>> {
    loop {
        print!("{label}: ");
        io::stdout().flush().context("Failed to write prompt")?;
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .context("Failed to read input")?;
        let value = line.trim();
        if value.is_empty() {
            return Ok(None);
        }
        match value.parse::<u16>() {
            Ok(port) => return Ok(Some(port)),
            Err(_) => eprintln!("Enter a port number (1-65535) or leave blank."),
        }
    }
}
