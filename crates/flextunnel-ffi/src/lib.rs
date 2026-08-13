//! C FFI surface for the iOS app (`aarch64-apple-ios`).
//!
//! The app links `libflextunnel.xcframework` (containing `libflextunnel.a`
//! slices) and drives the in-process tunnel primarily with these calls:
//!
//! 1. [`flextunnel_start`] — parse the JSON config, create an iroh endpoint,
//!    optionally bind a loopback SOCKS5 listener, and spawn the
//!    connect/auth/serve loop on an embedded runtime. Returns an opaque handle
//!    and writes `{"socks_port": N|null}` to the caller's buffer so the app can point
//!    `WKWebsiteDataStore.proxyConfigurations` at `127.0.0.1:N`. At most **one**
//!    instance may run at a time (a process-global guard rejects a second).
//! 2. [`flextunnel_set_forwards`] — reconcile server-direct local forwards.
//! 3. [`flextunnel_health`] — cheap liveness probe: is the serve loop still
//!    running, or did it give up (bad node id / auth / unreachable server)?
//! 4. [`flextunnel_routes`] — snapshot the server-pushed split-tunnel set for UI.
//! 5. [`flextunnel_conn_path`] — snapshot the live iroh path(s) (relay/direct)
//!    for an on-demand "connection path" status readout.
//! 6. [`flextunnel_stop`] — abort the loop, close the endpoint, free the handle.
//!
//! Unlike the ezvpn FFI there is **no VPN / Network Extension and no `utun` fd**:
//! flextunnel is pure-userspace proxying and server-direct forwarding over QUIC,
//! so its optional proxy and forwarding listeners run entirely inside the app
//! process. The app is expected to work only in the foreground —
//! when iOS suspends it the runtime freezes and the QUIC connection idle-times
//! out; the reconnect loop re-establishes on return to the foreground.
//!
//! All functions are null-safe and never unwind across the FFI boundary (the
//! release profile is `panic = "abort"`, so a panic terminates the process
//! rather than crossing into Swift).
//!
//! ## Config JSON (input to `flextunnel_start`)
//!
//! `auth_token` and `server_node_id` are required; the rest are optional. The
//! routed set (the *tunnel set* that decides split-tunneling) is configured on
//! the server and pushed to the client during the handshake, so the app sends
//! no routed set of its own.
//!
//! ```json
//! {
//!   "server_node_id": "<iroh endpoint id>",
//!   "auth_token": "<flextunnel auth token>",
//!   "socks_port": null,
//!   "relay_urls": ["https://relay.example/"],
//!   "relay_auth_token": null
//! }
//! ```
//!
//! ## Result JSON (output of `flextunnel_start` on success)
//!
//! ```json
//! { "socks_port": null }
//! ```

use std::ffi::{CStr, c_char, c_int};
use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddr};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use tokio::net::TcpListener;

use flextunnel_core::error::ProxyResult;
use flextunnel_core::proxy::signaling::Target;
use flextunnel_core::proxy::{
    ClientAuth, ClientConfig, ForwardManager, ForwardSpec, ForwardState, ProxyClient, TunnelRoutes,
};
use flextunnel_core::transport::endpoint::{RelayConfig, create_client_endpoint};
use flextunnel_core::transport::paths::ConnPathKind;

/// Process-global guard enforcing **at most one** running proxy instance. A
/// second [`flextunnel_start`] while one is live is rejected rather than racing.
/// Claimed on a successful start, released by [`flextunnel_stop`] (or any start
/// failure path).
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Opaque handle owned by the Swift side. Created by [`flextunnel_start`], freed
/// by [`flextunnel_stop`].
pub struct FlextunnelHandle {
    runtime: tokio::runtime::Runtime,
    /// Kept so [`flextunnel_stop`] can close it gracefully before drop.
    endpoint: iroh::Endpoint,
    /// The client driving the serve loop. Shared with the spawned `task` (which
    /// holds a clone) so status callers can snapshot its live iroh paths on
    /// demand via [`flextunnel_conn_path`].
    client: Arc<ProxyClient>,
    /// The running connect/serve loop.
    task: tokio::task::JoinHandle<ProxyResult<()>>,
    /// Live tunnel set (split-tunnel domains/CIDRs the server pushed), refreshed
    /// by the serve loop on each (re)connect. Read by [`flextunnel_routes`].
    routes: Arc<Mutex<TunnelRoutes>>,
    /// Server-direct local forward listeners, reconciled from Swift.
    forwards: Mutex<ForwardManager>,
}

#[derive(Deserialize)]
struct FfiConfig {
    server_node_id: String,
    auth_token: String,
    /// Loopback SOCKS5 port to bind. `None` disables the SOCKS5 front-end;
    /// `Some(0)` binds an OS-assigned ephemeral port.
    #[serde(default)]
    socks_port: Option<u16>,
    #[serde(default)]
    relay_urls: Vec<String>,
    /// Shared bearer token sent to every custom relay's WebSocket upgrade. Only
    /// valid with custom `relay_urls`; rejected with the default iroh relays.
    #[serde(default)]
    relay_auth_token: Option<String>,
}

#[derive(Deserialize)]
struct FfiForward {
    id: String,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
    enabled: bool,
}

/// Initialize logging (stderr -> unified log / Console). Honors `RUST_LOG`,
/// otherwise keeps flextunnel's own crates at `info` while quieting noisy
/// dependencies (iroh and friends) to `warn`. Idempotent; safe to call more
/// than once.
///
/// # Safety
/// No arguments; always safe to call.
#[unsafe(no_mangle)]
pub extern "C" fn flextunnel_init_logging() {
    flextunnel_core::app::init_logger(
        "warn,flextunnel_core=info,flextunnel_ffi=info,flextunnel_cli=info",
    );
}

/// Start the in-process tunnel, optionally with a SOCKS5 front-end.
///
/// Returns a non-null handle on success and writes `{"socks_port": N|null}` to
/// `out_buf`. On failure returns null and writes an error message to `out_buf`.
/// If `out_buf` is too small for the result JSON, that is treated as a failure
/// (null returned, no handle leaked) — retry with a larger buffer.
///
/// # Safety
/// - `config_json` must be a valid, NUL-terminated UTF-8 C string.
/// - `out_buf` must point to at least `out_len` writable bytes (may be null only
///   if `out_len` is 0).
/// - The returned pointer must be freed exactly once with [`flextunnel_stop`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_start(
    config_json: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> *mut FlextunnelHandle {
    if config_json.is_null() {
        write_cstr(out_buf, out_len, "config_json is null");
        return ptr::null_mut();
    }
    let json = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s,
        Err(_) => {
            write_cstr(out_buf, out_len, "config_json is not valid UTF-8");
            return ptr::null_mut();
        }
    };

    // Enforce a single running instance. Claim the guard before doing any work;
    // every failure path below releases it so a later start can succeed.
    if RUNNING
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        write_cstr(
            out_buf,
            out_len,
            "a flextunnel proxy is already running; stop it first",
        );
        return ptr::null_mut();
    }

    match start_inner(json) {
        Ok((handle, result_json)) => {
            // Refuse to hand back a handle if the result JSON did not fit: the
            // caller would not learn the port. Stop the loop, free, and signal
            // failure so the caller retries with a larger buffer.
            if write_cstr(out_buf, out_len, &result_json) {
                Box::into_raw(Box::new(handle))
            } else {
                stop_handle(handle);
                RUNNING.store(false, Ordering::Release);
                write_cstr(out_buf, out_len, "out_buf too small for result JSON");
                ptr::null_mut()
            }
        }
        Err(msg) => {
            RUNNING.store(false, Ordering::Release);
            write_cstr(out_buf, out_len, &msg);
            ptr::null_mut()
        }
    }
}

fn start_inner(json: &str) -> Result<(FlextunnelHandle, String), String> {
    // The proxy holds a socket per connection; lift the app process's soft fd
    // limit (per-process, best-effort) before serving.
    flextunnel_core::app::raise_fd_limit();

    let cfg: FfiConfig =
        serde_json::from_str(json).map_err(|e| format!("invalid config JSON: {e}"))?;

    let runtime = flextunnel_core::app::build_runtime()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;

    // Browser sessions bind a SOCKS listener; forwarding-only sessions pass
    // null and have no local proxy front-end at all.
    let (listener, port) = match cfg.socks_port {
        Some(requested) => {
            let listener = runtime
                .block_on(TcpListener::bind((Ipv4Addr::LOCALHOST, requested)))
                .map_err(|e| {
                    if requested == 0 {
                        format!("failed to bind an ephemeral loopback SOCKS port: {e}")
                    } else {
                        format!("failed to bind 127.0.0.1:{requested} (already in use?): {e}")
                    }
                })?;
            let port = listener
                .local_addr()
                .map_err(|e| format!("failed to read bound SOCKS port: {e}"))?
                .port();
            (Some(listener), Some(port))
        }
        None => (None, None),
    };

    let relay_config = RelayConfig::from_urls_with_token(&cfg.relay_urls, cfg.relay_auth_token.clone())
        .map_err(|e| format!("invalid relay configuration: {e}"))?;
    let endpoint = runtime
        .block_on(create_client_endpoint(&relay_config))
        .map_err(|e| format!("failed to create iroh endpoint: {e}"))?;

    let client = Arc::new(ProxyClient::new(ClientConfig {
        server_node_id: cfg.server_node_id,
        auth: ClientAuth::Token(cfg.auth_token),
        // Unused: any listener is already bound above and passed in directly.
        socks_listen: port.map(|p| SocketAddr::from((Ipv4Addr::LOCALHOST, p))),
        // iOS exposes no HTTP front-end.
        http_listen: None,
        relay_urls: cfg.relay_urls,
        relay_auth_token: cfg.relay_auth_token,
        auto_reconnect: true,
        max_reconnect_attempts: None,
    }));

    // Share the live tunnel set out of the client, so `flextunnel_routes` can
    // read what the server pushes on connect.
    let routes = client.routes();
    let forwards = Mutex::new(ForwardManager::new(
        runtime.handle().clone(),
        client.server_forwarder(),
        &[],
    ));

    // Clone the endpoint into the task; the original stays in the handle so
    // `flextunnel_stop` can close it after aborting the task. The client is
    // shared (Arc) so the handle keeps a clone for `flextunnel_conn_path` while
    // the task drives the serve loop.
    let ep = endpoint.clone();
    let client_task = client.clone();
    let task = runtime.spawn(async move {
        client_task
            .run_with_optional_listeners(&ep, listener, None)
            .await
    });

    let result_json = serde_json::json!({ "socks_port": port }).to_string();
    Ok((
        FlextunnelHandle {
            runtime,
            endpoint,
            client,
            task,
            routes,
            forwards,
        },
        result_json,
    ))
}

/// Replace the complete desired server-direct forward set.
///
/// `forwards_json` is a JSON array of
/// `{id,local_port,remote_host,remote_port,enabled}` objects. Enabled forwards
/// bind `127.0.0.1` and `::1`; every accepted connection is sent directly over
/// the authenticated server connection. The server rejects off-list targets.
///
/// Returns 1 on success, 0 for invalid input, and -1 for a null handle.
///
/// # Safety
/// - `forwards_json` must be a valid, NUL-terminated JSON C string (required by
///   `CStr::from_ptr`); it may be null, which is treated as invalid input.
/// - `out_buf` must be valid for `out_len` bytes when non-null, and the handle
///   must still be owned by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_set_forwards(
    handle: *const FlextunnelHandle,
    forwards_json: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        write_cstr(out_buf, out_len, "null handle or forwards_json");
        return -1;
    }
    if forwards_json.is_null() {
        write_cstr(out_buf, out_len, "null handle or forwards_json");
        return 0;
    }
    let json = match unsafe { CStr::from_ptr(forwards_json) }.to_str() {
        Ok(json) => json,
        Err(_) => {
            write_cstr(out_buf, out_len, "forwards_json is not valid UTF-8");
            return 0;
        }
    };
    let configured: Vec<FfiForward> = match serde_json::from_str(json) {
        Ok(configured) => configured,
        Err(e) => {
            write_cstr(out_buf, out_len, &format!("invalid forwards JSON: {e}"));
            return 0;
        }
    };
    let mut ids = HashSet::new();
    let mut ports = HashSet::new();
    let mut specs = Vec::new();
    for forward in configured.into_iter().filter(|forward| forward.enabled) {
        if forward.id.is_empty() || !ids.insert(forward.id.clone()) {
            write_cstr(out_buf, out_len, "forward ids must be non-empty and unique");
            return 0;
        }
        if forward.local_port == 0 || !ports.insert(forward.local_port) {
            write_cstr(out_buf, out_len, "enabled forward local ports must be nonzero and unique");
            return 0;
        }
        let remote_host = forward.remote_host.trim();
        if remote_host.is_empty() || forward.remote_port == 0 {
            write_cstr(out_buf, out_len, "forward targets require a host and nonzero port");
            return 0;
        }
        specs.push(ForwardSpec {
            id: forward.id,
            local_port: forward.local_port,
            target: Target::Domain(remote_host.to_string(), forward.remote_port),
        });
    }
    let handle = unsafe { &*handle };
    match handle.forwards.lock() {
        Ok(mut manager) => manager.apply(&specs),
        Err(_) => {
            write_cstr(out_buf, out_len, "forward manager lock failed");
            return 0;
        }
    }
    write_cstr(out_buf, out_len, "");
    1
}

/// Snapshot server-direct forward states as JSON.
///
/// Returns 1 on success, 0 when the output buffer is too small, and -1 for a
/// null handle or internal lock failure.
///
/// # Safety
/// The handle must still be owned by the caller, and `out_buf` must be valid
/// for `out_len` bytes when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_forward_statuses(
    handle: *const FlextunnelHandle,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        write_cstr(out_buf, out_len, "");
        return -1;
    }
    let handle = unsafe { &*handle };
    let statuses = match handle.forwards.lock() {
        Ok(manager) => manager.statuses(),
        Err(_) => {
            write_cstr(out_buf, out_len, "");
            return -1;
        }
    };
    let statuses: Vec<_> = statuses
        .into_iter()
        .map(|status| {
            let (state, error) = match status.state {
                ForwardState::Starting => ("starting", None),
                ForwardState::Listening => ("listening", None),
                ForwardState::Failed(error) => ("failed", Some(error)),
            };
            serde_json::json!({
                "id": status.id,
                "state": state,
                "error": error,
                "active": status.active,
                "last_conn_error": status.last_conn_error,
            })
        })
        .collect();
    let json = serde_json::json!({ "forwards": statuses }).to_string();
    if write_cstr(out_buf, out_len, &json) { 1 } else { 0 }
}

/// Stop the proxy and free the handle. After this call `handle` is invalid and
/// must not be used again. Passing null is a safe no-op.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not
/// already freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_stop(handle: *mut FlextunnelHandle) {
    if handle.is_null() {
        return;
    }
    stop_handle(*unsafe { Box::from_raw(handle) });
    // Release the single-instance guard so a subsequent start can succeed.
    RUNNING.store(false, Ordering::Release);
}

/// Liveness probe for the running proxy.
///
/// Returns `1` while the connect/serve loop is still running, `0` once it has
/// ended (it gives up on a fatal error — bad node id, auth failure, or an
/// unreachable server on the *first* connect; transient drops after a successful
/// connect keep retrying and stay `1`), and `-1` for a null handle.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not yet
/// passed to [`flextunnel_stop`]. Passing null returns `-1`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_health(handle: *const FlextunnelHandle) -> c_int {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    if handle.task.is_finished() { 0 } else { 1 }
}

/// Snapshot the tunnel's current forwarding set as JSON into `out_buf`:
///
/// ```json
/// { "connected": true, "domains": ["*.example.com"], "cidrs": ["10.0.0.0/8"],
///   "host_aliases": [["nas.internal", "192.168.1.9"]],
///   "dns_forwards": [{"suffix": "corp.example.com", "servers": ["10.1.0.10:5353"]}],
///   "bridges": [{"name": "lab", "endpoint_id": "…", "domains": ["*.svc"], "cidrs": ["fd34::/64"]}] }
/// ```
///
/// This is the split-tunnel set the server pushes during the handshake — the
/// domains/CIDRs routed through the tunnel. The local SOCKS proxy owns the split:
/// matching targets use the tunnel, while off-list targets connect directly from
/// the client device. The server independently rejects any off-list request that
/// reaches it. The caller may use the lists for OS routing or display, but does
/// not need to enforce the split itself. Before the first successful handshake,
/// `connected` is false and the lists are empty. The set becomes available shortly
/// after start, once the handshake completes, so the caller should poll it.
///
/// `host_aliases` (`[alias, target]` pairs) is informational, for display in
/// status UIs only — the server resolves the aliases itself, so there is
/// nothing to enforce caller-side.
///
/// `dns_forwards` is the server's conditional DNS-forwarding table (split-DNS),
/// also informational: each entry is `{"suffix", "servers"}` where names under
/// `suffix` are resolved via `servers` (`IP` or `IP:port`) instead of the
/// server's system resolver. Empty when the server configures none.
///
/// `bridges` is the server's outbound bridge-route table (targets it forwards
/// to another flextunnel server), also informational: each entry is
/// `{"name", "endpoint_id", "domains", "cidrs"}`. The bridged rules are already
/// part of the routed set, so there is nothing to enforce caller-side. Empty
/// when the server configures none.
///
/// Returns `1` on success (full JSON written), `0` if `out_buf` was too small
/// (the JSON is truncated; retry with a larger buffer), and `-1` for a null
/// handle or if the route snapshot could not be read (internal lock error).
/// `out_buf` is always NUL-terminated when usable (non-null, `out_len > 0`):
/// the error returns write an empty string.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not yet
/// passed to [`flextunnel_stop`]. `out_buf` must point to at least `out_len`
/// writable bytes (may be null only if `out_len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_routes(
    handle: *const FlextunnelHandle,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        write_cstr(out_buf, out_len, "");
        return -1;
    }
    let handle = unsafe { &*handle };
    let json = match handle.routes.lock() {
        Ok(routes) => {
            let dns_forwards: Vec<_> = routes
                .dns_forwards
                .iter()
                .map(|(suffix, servers)| {
                    serde_json::json!({ "suffix": suffix, "servers": servers })
                })
                .collect();
            let bridges: Vec<_> = routes
                .bridges
                .iter()
                .map(|b| {
                    serde_json::json!({
                        "name": b.name,
                        "endpoint_id": b.endpoint_id,
                        "domains": b.domains,
                        "cidrs": b.cidrs,
                    })
                })
                .collect();
            serde_json::json!({
                "connected": routes.connected,
                "domains": routes.domains,
                "cidrs": routes.cidrs,
                "host_aliases": routes.host_aliases,
                "dns_forwards": dns_forwards,
                "bridges": bridges,
            })
            .to_string()
        }
        Err(_) => {
            write_cstr(out_buf, out_len, "");
            return -1;
        }
    };
    if write_cstr(out_buf, out_len, &json) { 1 } else { 0 }
}

/// Snapshot the live connection's iroh path(s) as JSON into `out_buf`, mirroring
/// `ezvpn client status` / the desktop's "connection path" readout:
///
/// ```json
/// { "paths": [
///     {"kind":"direct","display":"Direct 1.2.3.4:52186 (rtt 1ms)","selected":true},
///     {"kind":"relay","display":"Relay https://relay.example/ (rtt 42ms)","selected":false}
/// ] }
/// ```
///
/// This is a **point-in-time** snapshot of how the client currently reaches the
/// server, showing *all* discovered paths (not just the selected one); `kind` is
/// `"direct"`, `"relay"`, or `"other"` (a forward-compatible catch-all) and
/// `selected` marks the path iroh routes over right now. The `paths` array is
/// **empty** while disconnected (during a drop/backoff or before the first
/// connect), so callers should only offer this once the tunnel link is up.
///
/// `custom_relays` reports each configured custom relay's health from an
/// on-demand GET of its `/healthz` endpoint (checked in parallel, only when this
/// snapshot is requested). `working` is `true` on a 2xx, `false` when
/// unreachable/timed-out/non-2xx, and `null` if the check could not run; `error`
/// carries the failure detail. The array is empty when the default relays are
/// used. `/healthz` is unauthenticated: it confirms the relay is up, not that a
/// `relay_auth_token` is accepted.
///
/// Returns `1` on success (full JSON written), `0` if `out_buf` was too small
/// (the JSON is truncated; retry with a larger buffer), and `-1` for a null
/// handle. `out_buf` is always NUL-terminated when usable (non-null,
/// `out_len > 0`): the null-handle return writes an empty string.
///
/// # Safety
/// `handle` must be a valid pointer returned by [`flextunnel_start`] and not yet
/// passed to [`flextunnel_stop`]. `out_buf` must point to at least `out_len`
/// writable bytes (may be null only if `out_len` is 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flextunnel_conn_path(
    handle: *const FlextunnelHandle,
    out_buf: *mut c_char,
    out_len: usize,
) -> c_int {
    if handle.is_null() {
        write_cstr(out_buf, out_len, "");
        return -1;
    }
    let handle = unsafe { &*handle };
    // The relay health check performs on-demand HTTP, so drive the async snapshot
    // on the embedded runtime. Called from the app's own thread (never a runtime
    // worker), so `block_on` is safe and does not stall the running tunnel task.
    let snapshot = handle.runtime.block_on(handle.client.connection_snapshot());
    let paths: Vec<_> = snapshot
        .paths
        .into_iter()
        .map(|p| {
            let kind = match p.kind {
                ConnPathKind::Direct => "direct",
                ConnPathKind::Relay => "relay",
                ConnPathKind::Other => "other",
            };
            serde_json::json!({ "kind": kind, "display": p.display, "selected": p.selected })
        })
        .collect();
    let custom_relays: Vec<_> = snapshot
        .custom_relays
        .into_iter()
        .map(|r| serde_json::json!({ "url": r.url, "working": r.working, "error": r.error }))
        .collect();
    let json =
        serde_json::json!({ "paths": paths, "custom_relays": custom_relays }).to_string();
    if write_cstr(out_buf, out_len, &json) { 1 } else { 0 }
}

/// Abort the serve loop, close the endpoint gracefully, and shut the runtime
/// down. Factored out so [`flextunnel_start`] can also use it on the
/// buffer-too-small path without going through a raw pointer.
fn stop_handle(handle: FlextunnelHandle) {
    let FlextunnelHandle {
        runtime,
        endpoint,
        client: _,
        task,
        routes: _,
        forwards,
    } = handle;
    drop(forwards);
    task.abort();
    // Close the endpoint before it drops. Skipping this makes iroh tear down its
    // relay tasks ungracefully (a JoinSet abort that panics — fatal under
    // panic=abort). `block_on` is safe here: the task is already aborted.
    runtime.block_on(endpoint.close());
    runtime.shutdown_background();
}

/// Write `s` (always NUL-terminated) into the caller buffer. Returns `true` if
/// the full string fit, `false` if it was truncated or the buffer was unusable.
fn write_cstr(buf: *mut c_char, len: usize, s: &str) -> bool {
    if buf.is_null() || len == 0 {
        return false;
    }
    let bytes = s.as_bytes();
    // Reserve one byte for the trailing NUL.
    let copy = bytes.len().min(len - 1);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, copy);
        *buf.add(copy) = 0;
    }
    copy == bytes.len()
}
