//! flextunnel
//!
//! A SOCKS5/HTTP-proxy-over-QUIC split tunnel via iroh P2P connections. The
//! client runs optional local SOCKS5/HTTP proxy listeners and server-direct
//! port forwards (managed live from `flextunnel client control`); routed
//! targets are tunneled as reliable QUIC bi-streams to the server, which
//! resolves DNS and connects from its own network. Uses a fixed ALPN for
//! protocol selection, client keypairs (ed25519) for access control, and TLS
//! 1.3/QUIC for encryption. Neither side needs admin/root (no TUN device).

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::io::IsTerminal;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

mod client_session;
mod forwards;
mod instance;
mod ipc;
mod lock;
mod prompt;
mod tui;

use flextunnel_core::app;
use flextunnel_core::blocklist::BlockList;
use flextunnel_core::iroh::{EndpointId, SecretKey};
use flextunnel_core::proxy::{
    BridgeUpstream, BridgeUpstreamConfig, DnsForwarder, ProxyServer, ProxyServerParams, RoutedSet,
};
use flextunnel_core::secret::secret_to_endpoint_id;
use flextunnel_core::transport::endpoint::{
    EndpointAllowlists, RelayConfig, create_server_endpoint,
};
use flextunnel_core::{auth, config, secret};

#[derive(Parser)]
#[command(name = "flextunnel")]
#[command(version)]
#[command(about = "SOCKS5/HTTP-proxy-over-QUIC split tunnel via iroh P2P")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the proxy server.
    #[command(arg_required_else_help = true)]
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// Start or control the proxy client.
    #[command(arg_required_else_help = true)]
    Client {
        #[command(subcommand)]
        action: ClientAction,
    },
    /// Generate a new iroh private key for persistent server identity.
    GenerateIrohKey {
        /// Path where to save the private key file. Defaults to stdout ("-").
        #[arg(short, long, default_value = "-")]
        output: PathBuf,
        /// Overwrite existing file if it exists.
        #[arg(long)]
        force: bool,
        /// Print machine-readable JSON to stdout (for automation).
        #[arg(long)]
        json: bool,
    },
    /// Show the public iroh id (EndpointId) derived from an iroh private key.
    #[command(arg_required_else_help = true)]
    ShowIrohId {
        /// Config file path (TOML). CLI flags override file values.
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Load config from ~/.config/flextunnel/server.toml.
        #[arg(long)]
        default_config: bool,
        /// Path to the private key file (overrides secret_file/secret in the config).
        #[arg(short, long)]
        secret_file: Option<PathBuf>,
        /// Print machine-readable JSON to stdout (for automation).
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ServerAction {
    /// Start the proxy server (SOCKS5/HTTP proxy over QUIC). Needs at least one
    /// flag: `-c`/other options load a config (the default
    /// ~/.config/flextunnel/server.toml with --default-config), or `--quick`
    /// runs an ephemeral one-off server. Run with no arguments to print this help.
    #[command(arg_required_else_help = true)]
    Start {
        /// Config file path (TOML). CLI flags override file values.
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Load config from ~/.config/flextunnel/server.toml.
        #[arg(long)]
        default_config: bool,
        /// Secret key file for the server's persistent identity.
        #[arg(long)]
        secret_file: Option<PathBuf>,
        /// File of authorized client public keys (ssh authorized_keys style:
        /// one `ed25519-pub:...` per line, optional trailing comment).
        #[arg(long)]
        authorized_keys_file: Option<PathBuf>,
        /// Custom relay server URL(s) for failover (repeatable).
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,
        /// Shared bearer token sent to every custom relay (custom relays only).
        #[arg(long)]
        relay_auth_token: Option<String>,
        /// Ephemeral one-off server. Run `client start --quick` FIRST — it
        /// prints the client's EndpointId; enter that id at this server's
        /// prompt to allowlist it as the only allowed client (no auth
        /// keypair). Generates an in-memory identity, full-tunnels all
        /// traffic, prints this server's EndpointId to enter back at the
        /// client's prompt, and exits if the client doesn't connect within 5
        /// minutes. Needs an interactive terminal. Nothing is persisted.
        #[arg(
            long,
            conflicts_with_all = ["config", "default_config", "secret_file",
                "authorized_keys_file"]
        )]
        quick: bool,
    },
}

#[derive(Subcommand)]
enum ClientAction {
    /// Start the proxy client (optional SOCKS5 + HTTP proxy listeners, port
    /// forwards). Needs at least one flag: `-c`/other options load a config (the
    /// default ~/.config/flextunnel/client.toml when no -c is given), or
    /// `--quick` prompts for the connection details without persisting them. Run
    /// with no arguments to print this help.
    #[command(arg_required_else_help = true)]
    Start {
        /// Config file path (TOML). CLI flags override file values. Without
        /// this, ~/.config/flextunnel/client.toml is used if it exists.
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Loopback port for the optional SOCKS5 listener (binds 127.0.0.1
        /// only), e.g. 1080. Disabled unless set here or in the config.
        #[arg(long)]
        socks_port: Option<u16>,
        /// Loopback port for the optional HTTP proxy listener (CONNECT +
        /// plain-HTTP forwarding; binds 127.0.0.1 only), e.g. 8081. Disabled
        /// unless set.
        #[arg(long)]
        http_port: Option<u16>,
        /// EndpointId of the server to connect to.
        #[arg(short = 'n', long)]
        server_node_id: Option<String>,
        /// Inline client secret key (`ed25519-sec:...`) used to
        /// authenticate to the server.
        #[arg(long, conflicts_with = "auth_key_file")]
        auth_key: Option<String>,
        /// File containing the client secret key (from `flexaccess-keys
        /// generate-auth-key`).
        #[arg(long)]
        auth_key_file: Option<PathBuf>,
        /// Custom relay server URL(s) for failover (repeatable).
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,
        /// Shared bearer token sent to every custom relay (custom relays only).
        #[arg(long)]
        relay_auth_token: Option<String>,
        /// Force auto-reconnect on (overrides `auto_reconnect = false` in the config).
        #[arg(long, conflicts_with = "no_auto_reconnect")]
        auto_reconnect: bool,
        /// Disable auto-reconnect (exit on the first disconnection).
        #[arg(long, conflicts_with = "auto_reconnect")]
        no_auto_reconnect: bool,
        /// Cap on reconnect attempts between successful connections (unlimited if unset).
        #[arg(long)]
        max_reconnect_attempts: Option<NonZeroU32>,
        /// Ignore any saved config, print this client's EndpointId (enter it on
        /// the quick server, which allowlists it — no auth keypair), and
        /// prompt for the server EndpointId (pairs with `server start
        /// --quick`). Nothing is persisted.
        #[arg(long, conflicts_with_all = ["config", "auth_key", "auth_key_file"])]
        quick: bool,
    },
    /// Attach the control panel to the running client for a profile: live
    /// status + editable port forwards (in this terminal). The client is
    /// identified by the profile's server node id; with no flags, the default
    /// config (~/.config/flextunnel/client.toml) selects it.
    Control {
        /// Config file path (TOML) of the profile to attach to. With no flags,
        /// ~/.config/flextunnel/client.toml selects the profile.
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,
        /// Attach by server EndpointId directly (overrides the config file).
        #[arg(short = 'n', long)]
        server_node_id: Option<String>,
    },
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::error::ErrorKind;

    #[test]
    fn client_requires_an_action() {
        let Err(error) = Args::try_parse_from(["flextunnel", "client"]) else {
            panic!("client without an action must be rejected");
        };
        assert_eq!(
            error.kind(),
            ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
    }

    #[test]
    fn client_start_accepts_startup_flags() {
        let args = Args::try_parse_from([
            "flextunnel",
            "client",
            "start",
            "--server-node-id",
            "server-id",
            "--auth-key",
            "ed25519-sec:XXXX",
        ])
        .unwrap_or_else(|error| panic!("client start should parse: {error}"));

        assert!(matches!(
            args.command,
            Command::Client {
                action: ClientAction::Start { .. }
            }
        ));
    }

    #[test]
    fn bare_start_subcommands_show_help() {
        // `client start` / `server start` with no flags print help rather than
        // starting (arg_required_else_help): there is nothing to run with.
        for args in [
            ["flextunnel", "client", "start"],
            ["flextunnel", "server", "start"],
        ] {
            let Err(error) = Args::try_parse_from(args) else {
                panic!("bare {args:?} must display help, not parse");
            };
            assert_eq!(
                error.kind(),
                ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
                "{args:?}"
            );
        }
    }

    #[test]
    fn start_subcommands_parse_with_one_flag() {
        // A single flag satisfies arg_required_else_help and reaches dispatch.
        Args::try_parse_from(["flextunnel", "client", "start", "--socks-port", "1080"])
            .unwrap_or_else(|error| panic!("client start with a flag should parse: {error}"));
        Args::try_parse_from(["flextunnel", "server", "start", "--default-config"])
            .unwrap_or_else(|error| panic!("server start with a flag should parse: {error}"));
    }

    #[test]
    fn client_rejects_removed_default_config_flag() {
        for action in ["start", "control"] {
            let Err(error) =
                Args::try_parse_from(["flextunnel", "client", action, "--default-config"])
            else {
                panic!("--default-config must be rejected for client {action}");
            };
            assert_eq!(error.kind(), ErrorKind::UnknownArgument);
        }
    }

    #[test]
    fn client_rejects_legacy_startup_flags() {
        let Err(error) = Args::try_parse_from([
            "flextunnel",
            "client",
            "--server-node-id",
            "server-id",
        ]) else {
            panic!("startup flags without the start action must be rejected");
        };
        assert_eq!(error.kind(), ErrorKind::UnknownArgument);
    }

    #[test]
    fn server_start_parses_quick_flag() {
        let args = Args::try_parse_from(["flextunnel", "server", "start", "--quick"])
            .unwrap_or_else(|error| panic!("server start --quick should parse: {error}"));
        assert!(matches!(
            args.command,
            Command::Server {
                action: ServerAction::Start { quick: true, .. }
            }
        ));
    }

    #[test]
    fn client_start_parses_quick_flag() {
        let args = Args::try_parse_from(["flextunnel", "client", "start", "--quick"])
            .unwrap_or_else(|error| panic!("client start --quick should parse: {error}"));
        assert!(matches!(
            args.command,
            Command::Client {
                action: ClientAction::Start { quick: true, .. }
            }
        ));
    }

    #[test]
    fn quick_conflicts_with_config_and_secret() {
        // `--quick` mints everything ephemerally, so it is mutually exclusive
        // with the config/secret/key flags on both sides.
        let cases = [
            vec!["flextunnel", "server", "start", "--quick", "-c", "server.toml"],
            vec!["flextunnel", "server", "start", "--quick", "--secret-file", "k.key"],
            vec!["flextunnel", "server", "start", "--quick", "--authorized-keys-file", "ak.txt"],
            vec!["flextunnel", "client", "start", "--quick", "-c", "client.toml"],
            // Quick mode has no keypair auth at all (the credential is the
            // client's endpoint id), so key flags are rejected too.
            vec!["flextunnel", "client", "start", "--quick", "--auth-key", "ed25519-sec:X"],
            vec!["flextunnel", "client", "start", "--quick", "--auth-key-file", "c.key"],
        ];
        for case in cases {
            let Err(error) = Args::try_parse_from(&case) else {
                panic!("expected a conflict for {case:?}");
            };
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict, "{case:?}");
        }
    }

    #[test]
    fn quick_server_config_is_full_tunnel_without_client_keys() {
        let (cli, _secret) = quick_server_config(Vec::new(), None);
        // No keypair auth in quick mode: the allowlisted client endpoint id is
        // the sole credential. The ephemeral identity is returned alongside —
        // never through the config, which carries no key at all.
        assert_eq!(cli.authorized_keys_file, None);
        assert_eq!(cli.secret_file, None);
        // Full tunnel: the catch-alls for domains and both IP families.
        assert_eq!(cli.routed_domains.as_deref(), Some(["*".to_string()].as_slice()));
        assert_eq!(
            cli.routed_cidrs.as_deref(),
            Some(["0.0.0.0/0".to_string(), "::/0".to_string()].as_slice())
        );
        // The config resolves (validation passes).
        config::resolve_server(cli, None).expect("quick config must resolve");
    }

    #[test]
    fn client_help_lists_all_actions() {
        let Err(error) = Args::try_parse_from(["flextunnel", "client", "help"]) else {
            panic!("help is rendered as a clap display-help result");
        };
        assert_eq!(error.kind(), ErrorKind::DisplayHelp);
        let help = error.to_string();
        assert!(help.contains("start"));
        assert!(help.contains("control"));
        assert!(help.contains("help"));
    }
}

fn log_version() {
    app::log_version(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}

/// Whether the command is `client start --quick`, whose in-process TUI must own
/// the terminal without a logger writing over it.
fn is_quick_client_start(command: &Command) -> bool {
    matches!(
        command,
        Command::Client {
            action: ClientAction::Start { quick: true, .. }
        }
    )
}

fn main() -> Result<()> {
    let args = Args::parse();
    // `client start --quick` runs a full-screen control panel in this process;
    // an stderr logger would splatter log lines across it. Every other command
    // (including the detached `client control`, which is a separate process)
    // wants the logger. `log::*` calls are silent no-ops when it is not set.
    if !is_quick_client_start(&args.command) {
        app::init_logger(app::DEFAULT_LOG_FILTER);
    }

    match args.command {
        // The control panel drives the terminal with its own blocking event
        // loop (and a small runtime for the IPC calls), so it never enters the
        // shared multi-thread runtime below.
        Command::Client {
            action:
                ClientAction::Control {
                    config,
                    server_node_id,
                },
        } => tui::run(config, server_node_id),
        Command::GenerateIrohKey { output, force, json } => {
            secret::generate_iroh_key(output, force, json)
        }
        Command::ShowIrohId {
            config,
            default_config,
            secret_file,
            json,
        } => {
            // Resolve the secret the same way the server does: an explicit
            // --secret-file wins, otherwise fall back to secret_file/secret in
            // the config file. Reuses `resolve_server` for the merge + tilde
            // expansion; no async runtime needed for this path.
            let cli = config::ServerConfig {
                secret_file,
                ..Default::default()
            };
            let file = config::load_server_config(config.as_deref(), default_config)?;
            let r = config::resolve_server(cli, file)?;
            secret::show_iroh_id(r.secret_file.as_deref(), json)
        }
        command => app::build_runtime()?.block_on(run_async(command)),
    }
}

async fn run_async(command: Command) -> Result<()> {
    // Long-running proxy processes hold a socket per connection; lift the soft
    // fd limit (per-process, best-effort) so macOS's default 256 doesn't choke
    // a busy client/server.
    app::raise_fd_limit();
    match command {
        Command::Server {
            action:
                ServerAction::Start {
                    config: config_path,
                    default_config,
                    secret_file,
                    authorized_keys_file,
                    relay_urls,
                    relay_auth_token,
                    quick,
                },
        } => {
            log_version();
            if quick {
                // Ephemeral one-off server: prompt for the client's endpoint id
                // and natively allowlist it as the only allowed (quick) client —
                // no auth keypair — then mint an in-memory identity, full-tunnel
                // everything, print the bootstrap, and exit if no client
                // connects within QUICK_IDLE_TIMEOUT. `--quick` conflicts with
                // the config/secret/token flags (clap-enforced), so the
                // ephemeral values are the whole configuration. The prompt
                // needs a TTY, so a piped `--quick` fails fast.
                if !std::io::stdin().is_terminal() {
                    anyhow::bail!("`server start --quick` needs an interactive terminal.");
                }
                println!(
                    "Quick mode — ephemeral server, full tunnel (all traffic routed). Nothing saved."
                );
                println!(
                    "Start the client first if you haven't: `flextunnel client start --quick` \
                     prints the client EndpointId to enter below."
                );
                let client_id = tokio::task::spawn_blocking(|| {
                    prompt::prompt_endpoint_id(
                        "Client EndpointId (shown by `flextunnel client start --quick`)",
                    )
                })
                .await??;
                let (cli, secret) = quick_server_config(relay_urls, relay_auth_token);
                print_quick_server_bootstrap(&secret_to_endpoint_id(&secret));
                return run_server(
                    config::resolve_server(cli, None)?,
                    Some(QuickServer { client_id, secret }),
                )
                .await;
            }
            let cli = config::ServerConfig {
                secret_file,
                authorized_keys_file,
                relay_urls: (!relay_urls.is_empty()).then_some(relay_urls),
                relay_auth_token,
                host_aliases: None, // config-file only; no CLI flag
                routed_domains: None, // config-file only; no CLI flag
                routed_cidrs: None,   // config-file only; no CLI flag
                dns_forwards: None,   // config-file only; no CLI flag
                bridges: None,        // config-file only; no CLI flag
                allowed_bridge_servers: None, // config-file only; no CLI flag
            };
            let file = config::load_server_config(config_path.as_deref(), default_config)?;
            run_server(config::resolve_server(cli, file)?, None).await
        }
        Command::Client {
            action:
                ClientAction::Start {
                    config: config_path,
                    socks_port,
                    http_port,
                    server_node_id,
                    auth_key,
                    auth_key_file,
                    relay_urls,
                    relay_auth_token,
                    auto_reconnect,
                    no_auto_reconnect,
                    max_reconnect_attempts,
                    quick,
                },
        } => {
            log_version();
            // CLI precedence: --auto-reconnect → Some(true), --no-auto-reconnect →
            // Some(false), neither → None (defer to config file, then default).
            // The two flags are mutually exclusive (clap `conflicts_with`).
            let auto_reconnect = if auto_reconnect {
                Some(true)
            } else if no_auto_reconnect {
                Some(false)
            } else {
                None
            };
            let mut cli = config::ClientConfig {
                server_node_id,
                name: None, // display name is config-file only; no CLI flag
                socks_port,
                http_port,
                auth_key,
                auth_key_file,
                relay_urls: (!relay_urls.is_empty()).then_some(relay_urls),
                relay_auth_token,
                auto_reconnect,
                max_reconnect_attempts,
            };
            // `--quick` is a self-contained ephemeral session: it ignores any
            // saved config, mints a session identity whose EndpointId is the
            // credential (printed here for the user to allowlist on the quick
            // server — no auth keypair), prompts for the remaining connection
            // details, and then runs a live control panel in this terminal
            // (pairs with `server start --quick`). Both the prompt and the
            // panel need a TTY, so a piped `--quick` fails fast instead of
            // hanging. Nothing is persisted and no control socket is exposed.
            // A bare `client start` never reaches here — clap prints help
            // (arg_required_else_help).
            if quick {
                if !std::io::stdin().is_terminal() {
                    anyhow::bail!("`client start --quick` needs an interactive terminal.");
                }
                let client_secret = SecretKey::generate();
                println!("Quick mode. Enter connection details (nothing will be saved):");
                println!(
                    "  Your client EndpointId: {}",
                    secret_to_endpoint_id(&client_secret)
                );
                println!(
                    "Enter it at the `flextunnel server start --quick` prompt — it is this \
                     client's credential (no auth keypair)."
                );
                cli = tokio::task::spawn_blocking(move || {
                    prompt::fill_client_config(&mut cli).map(|()| cli)
                })
                .await??;
                return client_session::run_quick(config::resolve_client(cli, None), client_secret)
                    .await;
            }
            let file = config::load_client_config(config_path.as_deref())?;
            client_session::run(config::resolve_client(cli, file)).await
        }
        _ => unreachable!("synchronous commands handled in main()"),
    }
}

/// Reject any conditional DNS-forwarding suffix the routed set does not cover.
/// Such a forward is dead config: the server rejects off-list targets before
/// resolution, so a suffix no routed rule reaches would never fire.
fn validate_dns_forwards_coverage(forwarder: &DnsForwarder, routed_set: &RoutedSet) -> Result<()> {
    for suffix in forwarder.suffixes() {
        if !routed_set.covers_suffix(suffix) {
            anyhow::bail!(
                "[dns_forwards] suffix {suffix:?} is not covered by the routed set, so it \
                 would never be used: the server rejects off-list targets before resolving \
                 them. Add \"*.{suffix}\" (and/or \"{suffix}\") to routed_domains, or remove \
                 the forward."
            );
        }
    }
    Ok(())
}

/// How long a `server start --quick` server waits for its first client before
/// exiting on its own. A one-shot grace window: once a client connects the timer
/// is cancelled for the rest of the process's life.
const QUICK_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Quick-mode (`server start --quick`) parameters for [`run_server`]: `Some`
/// arms the idle-exit grace timer, skips the single-instance lock and the
/// client-token requirement, and natively allowlists the one entered client id.
struct QuickServer {
    /// The single client endpoint id allowed to connect (over the quick ALPN);
    /// entered at the prompt, enforced by the endpoint's allowlist hook.
    client_id: EndpointId,
    /// The server's ephemeral in-memory identity. Carried here — never through
    /// the config, which quick mode does not use for keys.
    secret: SecretKey,
}

/// How long to wait for a graceful `endpoint.close()` during shutdown before
/// forcing exit. iroh's close normally completes promptly, but a lingering
/// relay/connection teardown must never leave the process unkillable.
const SHUTDOWN_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Build the ephemeral `ServerConfig` for `server start --quick`: a full-tunnel
/// routed set (`routed_domains = ["*"]`, `routed_cidrs = ["0.0.0.0/0", "::/0"]`)
/// plus a freshly generated in-memory identity, returned *alongside* the config —
/// quick mode never goes through config files, so no key rides in the config.
/// No client keys — the allowlisted client endpoint id is the sole credential.
/// Nothing is written to disk. `--relay-url` stays compatible with `--quick`,
/// so any relays are kept.
fn quick_server_config(
    relay_urls: Vec<String>,
    relay_auth_token: Option<String>,
) -> (config::ServerConfig, SecretKey) {
    let secret = SecretKey::generate();
    let cli = config::ServerConfig {
        routed_domains: Some(vec!["*".to_string()]),
        routed_cidrs: Some(vec!["0.0.0.0/0".to_string(), "::/0".to_string()]),
        relay_urls: (!relay_urls.is_empty()).then_some(relay_urls),
        relay_auth_token,
        ..Default::default()
    };
    (cli, secret)
}

/// Print the bootstrap line for a quick-mode server: the EndpointId to enter at
/// the client's prompt. The client is already running at this point — it was
/// started first to show the id just entered here — and is sitting at its
/// "Server EndpointId" prompt.
fn print_quick_server_bootstrap(endpoint_id: &EndpointId) {
    println!("  Server EndpointId: {endpoint_id}");
    println!("Enter it at the client's \"Server EndpointId\" prompt to connect.");
    println!("Waiting for the client — will exit in 5 minutes if it does not connect.");
}

async fn run_server(
    r: config::ResolvedServer,
    quick: Option<QuickServer>,
) -> Result<()> {
    // Enforce one server per user before doing any work (held for the process
    // lifetime; released automatically on exit or crash) — except a quick
    // ephemeral server, which is an intentional throwaway and takes no lock, so
    // it can run alongside a real server (or another quick one).
    let _lock = quick.is_none().then(lock::acquire).transpose()?;

    // A quick server runs without client keys: its single allowlisted client
    // id is the whole credential set (enforced natively by the endpoint's hook).
    let authorized_keys = match &r.authorized_keys_file {
        Some(path) => auth::load_authorized_keys(path)
            .context("Failed to load the authorized client keys")?,
        None => Default::default(),
    };
    if authorized_keys.is_empty() && quick.is_none() {
        anyhow::bail!(
            "The server requires at least one authorized client public key.\n\
             Each client generates a keypair with: flexaccess-keys generate-auth-key -o <FILE>\n\
             Put each key's authorized-key entry (one `ed25519-pub:...` per line, from \
             `flexaccess-keys show-auth-key --private-key-file <FILE>`) in a file and \
             pass --authorized-keys-file <FILE> or set authorized_keys_file in the config."
        );
    }
    match &quick {
        Some(q) => log::info!(
            "Quick mode: client {} allowlisted (endpoint-id credential; no client keys)",
            q.client_id
        ),
        None => log::info!("Loaded {} authorized client key(s)", authorized_keys.len()),
    }

    // A quick server's identity is the ephemeral in-memory key it carries;
    // a regular server's comes from its key file.
    let secret_key = match &quick {
        Some(q) => q.secret.clone(),
        None => secret::resolve_secret_key(r.secret_file.as_deref())?,
    };
    let own_id = secret_to_endpoint_id(&secret_key);

    // Load the duplicate-id blocklist and refuse to start if this server's own id
    // is recorded as a conflict (duplicate-server self-block guard). Done before
    // creating the endpoint so a self-blocked identity never binds.
    let blocklist = BlockList::load(r.blocklist_file.clone())
        .with_context(|| format!("Failed to load blocklist {}", r.blocklist_file.display()))?;
    if blocklist.is_server_conflicted(&own_id.to_string()) {
        anyhow::bail!(
            "Refusing to start: server id {own_id} is recorded as a duplicate-id conflict in \
             {}.\nAnother server was detected sharing this identity. Stop the other server, \
             then remove the entry from the blocklist to start again.",
            r.blocklist_file.display()
        );
    }

    // Parse the routed set before creating the endpoint: a parse failure here must
    // not bypass the endpoint.close() cleanup below (an ungraceful drop panics
    // under panic=abort).
    let routed_set = RoutedSet::new(&r.routed_domains, &r.routed_cidrs)
        .context("Invalid routed-set configuration")?;
    // The tunnel set is required (VPN-style split tunnel): decide explicitly what
    // is routed through the tunnel. Use "*" (and 0.0.0.0/0, ::/0) for full tunnel.
    if routed_set.is_empty() {
        anyhow::bail!(
            "a tunnel set is required: configure routed_domains / routed_cidrs \
             (use \"*\" plus 0.0.0.0/0 and ::/0 to tunnel all traffic)"
        );
    }

    // Build the conditional DNS-forwarding table before creating the endpoint so
    // a bad server spec fails fast (same reasoning as the routed set above).
    let dns_forwarder = DnsForwarder::new(&r.dns_forwards)
        .context("Invalid dns_forwards configuration")?;
    if let Some(forwarder) = &dns_forwarder {
        validate_dns_forwards_coverage(forwarder, &routed_set)?;
    }

    // Inbound bridging: parse the allowlist — the sole bridge credential,
    // enforced natively at the TLS handshake by the endpoint's allowlist hook.
    let allowed_bridge_servers = r
        .allowed_bridge_servers
        .iter()
        .map(|raw| {
            raw.parse::<EndpointId>()
                .map_err(|e| anyhow::anyhow!("invalid allowed_bridge_servers entry {raw:?}: {e}"))
        })
        .collect::<Result<std::collections::HashSet<_>>>()?;
    if allowed_bridge_servers.contains(&own_id) {
        anyhow::bail!(
            "allowed_bridge_servers contains this server's own id ({own_id}); a server \
             cannot bridge to itself — this is likely a copy-paste mistake"
        );
    }
    if !allowed_bridge_servers.is_empty() {
        log::info!(
            "Inbound bridging enabled for {} server(s)",
            allowed_bridge_servers.len()
        );
    }

    // Resolve the relay config once. Its URLs are installed on the endpoint and
    // also attached as address hints when outbound bridges dial peer servers.
    // The relay auth token remains endpoint-level state in the relay map.
    let relay_config = RelayConfig::from_urls_with_token(&r.relay_urls, r.relay_auth_token.clone())
        .context("Invalid relay configuration")?;

    // Outbound bridges: resolve each `[bridges.<name>]` entry (endpoint id,
    // rules) and reject rules the routed set never reaches — the server
    // rejects off-list targets before bridge routing, so such a rule is dead
    // config (same reasoning as the dns_forwards coverage check above).
    let mut bridges = Vec::with_capacity(r.bridges.len());
    for (name, b) in &r.bridges {
        let endpoint_id = b.endpoint_id.parse::<EndpointId>().map_err(|e| {
            anyhow::anyhow!("bridge '{name}' has an invalid endpoint_id {:?}: {e}", b.endpoint_id)
        })?;
        if endpoint_id == own_id {
            anyhow::bail!("bridge '{name}' targets this server itself ({own_id})");
        }
        let bridge_routed_set = RoutedSet::new(&b.domains, &b.cidrs)
            .with_context(|| format!("bridge '{name}' has invalid route rules"))?;
        routed_set
            .validate_rules_reachable(&b.domains, &b.cidrs)
            .with_context(|| {
                format!(
                    "bridge '{name}' has a rule the routed set never reaches, so it would \
                     never be used: the server rejects off-list targets before bridge \
                     routing. Add matching routed_domains/routed_cidrs, or remove the rule"
                )
            })?;
        bridges.push(BridgeUpstream::new(BridgeUpstreamConfig {
            name: name.clone(),
            endpoint_id,
            relay_urls: relay_config.custom_urls().to_vec(),
            routed_set: bridge_routed_set,
            domains: b.domains.clone(),
            cidrs: b.cidrs.clone(),
        }));
    }
    if !bridges.is_empty() {
        log::info!("Loaded {} bridge route(s)", bridges.len());
    }

    let allowlists = EndpointAllowlists {
        bridge_servers: allowed_bridge_servers.clone(),
        // Quick mode: the one entered client id, enforced natively at the TLS
        // handshake. Empty otherwise — the quick ALPN is then disabled.
        quick_clients: quick
            .as_ref()
            .map(|q| std::collections::HashSet::from([q.client_id]))
            .unwrap_or_default(),
    };
    let endpoint = create_server_endpoint(&relay_config, secret_key, allowlists)
        .await
        .context("Failed to create iroh endpoint")?;
    log::info!("flextunnel server Node ID: {}", endpoint.id());
    match &quick {
        Some(_) => log::info!(
            "Quick mode: enter this server's EndpointId ({}) at the waiting client's prompt",
            endpoint.id()
        ),
        None => log::info!(
            "Clients connect with: flextunnel client start --server-node-id {} --auth-key-file <KEY FILE>",
            endpoint.id()
        ),
    }

    if !r.host_aliases.is_empty() {
        log::info!("Loaded {} host alias(es)", r.host_aliases.len());
    }
    if !r.dns_forwards.is_empty() {
        log::info!(
            "Loaded {} conditional DNS-forwarding rule(s)",
            r.dns_forwards.len()
        );
    }
    log::info!(
        "Tunnel set: {} domain rule(s), {} CIDR(s) — off-list tunnel requests are rejected; pushed to clients on connect",
        r.routed_domains.len(),
        r.routed_cidrs.len()
    );
    // Quick mode arms an idle-exit timer; the server fires this on the first
    // client to cancel it. `None` for a normal server (the timer never runs).
    let first_client = quick.as_ref().map(|_| Arc::new(Notify::new()));
    let server = ProxyServer::new(ProxyServerParams {
        own_id,
        authorized_keys,
        allowed_bridge_servers,
        host_aliases: r.host_aliases,
        routed_set,
        routed_domains: r.routed_domains,
        routed_cidrs: r.routed_cidrs,
        dns_forwarder,
        bridges,
        blocklist,
        first_client: first_client.clone(),
    });
    // Quick-mode grace window: fire after `QUICK_IDLE_TIMEOUT` unless a client
    // connects first (which resolves `notified()` and parks this future
    // forever). `first_client` is `Some` exactly in quick mode; a normal server
    // parks here immediately, so the arm never fires. `notify_one` stores a
    // permit, so a client that connects before this future is first polled is
    // not missed.
    let mut grace = pin!(async {
        match &first_client {
            Some(notify) => {
                tokio::select! {
                    _ = notify.notified() => std::future::pending::<()>().await,
                    _ = tokio::time::sleep(QUICK_IDLE_TIMEOUT) => {}
                }
            }
            None => std::future::pending::<()>().await,
        }
    });
    let res = tokio::select! {
        res = Arc::clone(&server).run(&endpoint) => res.map_err(|e| anyhow::anyhow!("Server error: {e}")),
        sig = app::shutdown_signal() => sig.map(|()| {
            log::info!("Received shutdown signal, stopping server");
        }),
        _ = &mut grace => {
            log::warn!("Quick mode: no client connected within 5 minutes — exiting");
            Ok(())
        }
    };

    close_endpoint_or_exit(&endpoint).await;
    res
}

/// Close `endpoint` gracefully before it is dropped — skipping the close makes
/// iroh tear down its relay tasks via an ungraceful abort, which panics
/// (`JoinSet::join_all` on a cancelled task), fatal under panic=abort. But never
/// let a slow teardown make the process unkillable: once we are already shutting
/// down, a second shutdown signal (e.g. another Ctrl-C) or `SHUTDOWN_CLOSE_TIMEOUT`
/// forces an immediate clean exit. `std::process::exit` skips destructors, so it
/// avoids the very ungraceful-drop panic the graceful close exists to prevent.
/// Shared by the server ([`run_server`]) and the client (`client_session`).
pub(crate) async fn close_endpoint_or_exit(endpoint: &flextunnel_core::iroh::Endpoint) {
    tokio::select! {
        _ = endpoint.close() => {}
        _ = app::shutdown_signal() => {
            log::warn!("Second shutdown signal — exiting now");
            std::process::exit(0);
        }
        _ = tokio::time::sleep(SHUTDOWN_CLOSE_TIMEOUT) => {
            log::warn!("Endpoint close is taking too long — exiting now");
            std::process::exit(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn forwarder(suffix: &str) -> DnsForwarder {
        let mut m = HashMap::new();
        m.insert(suffix.to_string(), vec!["10.0.0.53".to_string()]);
        DnsForwarder::new(&m).unwrap().expect("one forward configured")
    }

    fn routed(domains: &[&str]) -> RoutedSet {
        let d: Vec<String> = domains.iter().map(|s| s.to_string()).collect();
        RoutedSet::new(&d, &[]).unwrap()
    }

    #[test]
    fn dns_forwards_coverage_accepts_covered_suffix() {
        let f = forwarder("local.168234.xyz");
        // A wildcard whose zone reaches the suffix makes the forward live.
        assert!(validate_dns_forwards_coverage(&f, &routed(&["*.local.168234.xyz"])).is_ok());
        assert!(validate_dns_forwards_coverage(&f, &routed(&["*"])).is_ok());
    }

    #[test]
    fn dns_forwards_coverage_rejects_uncovered_suffix() {
        let f = forwarder("local.168234.xyz");
        let err = validate_dns_forwards_coverage(&f, &routed(&["*.example.com"])).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("local.168234.xyz"), "{msg}");
        assert!(msg.contains("not covered"), "{msg}");
    }
}
