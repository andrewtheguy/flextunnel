/*
 * flextunnel.h — C interface to libflextunnel.xcframework for the iOS app.
 *
 * Build the static library slices with ./build-ios.sh (produces
 * dist/ios/libflextunnel.xcframework alongside a copy of this header).
 *
 * Unlike a VPN, there is no Network Extension and no utun fd. Browser sessions
 * may run a SOCKS5 listener for WKWebView; forwarding-only sessions omit it and
 * use server-direct local forward listeners owned by the Rust core.
 *
 * Lifecycle:
 *
 *   1. flextunnel_init_logging()                          (once, optional)
 *   2. flextunnel_start(configJson, buf, len) -> handle   (or NULL on error)
 *        On success `buf` holds {"socks_port": N|null};
 *        configure the WKWebView proxy with NWEndpoint host 127.0.0.1, port N.
 *        On error `buf` holds the error message. At most ONE instance may run
 *        at a time; a second start while one is live returns NULL.
 *   3. flextunnel_health(handle) -> 1 running / 0 ended / -1 null  (poll)
 *   -  flextunnel_conn_path(handle, buf, len)             (on-demand path readout)
 *   4. flextunnel_stop(handle)                            (on teardown)
 *
 * Pass a numeric "socks_port" to bind the browser's loopback SOCKS5 listener
 * (0 requests an OS-assigned port). Pass null or omit it for a forwarding-only
 * session with no SOCKS5 listener.
 *
 * All functions are NULL-safe and never unwind into Swift.
 */
#ifndef FLEXTUNNEL_H
#define FLEXTUNNEL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque session handle. Created by flextunnel_start, freed by flextunnel_stop. */
typedef struct FlextunnelHandle FlextunnelHandle;

/*
 * Initialize logging (stderr -> unified log / Console). Honors RUST_LOG,
 * defaults to "info". Idempotent; safe to call more than once.
 */
void flextunnel_init_logging(void);

/*
 * Generate a fresh client authentication keypair. Writes
 *   {"created":"<UTC>","public_key":"flextunnelpubv1:...",
 *    "secret_key":"flextunnelsecretv1:..."}
 * to out_buf. Store the secret key in the keychain; show the public key (never
 * a secret) for the user to put on the server's authorized-keys file.
 * Returns 1 on success, 0 if out_buf is too small.
 */
int flextunnel_generate_client_key(char *out_buf, size_t out_len);

/*
 * Derive the public key ("flextunnelpubv1:...") of a stored secret key, so the
 * app can display it unmasked without persisting it separately. On success
 * writes the public key to out_buf and returns 1; on failure (invalid secret,
 * small buffer) writes an error message and returns 0.
 */
int flextunnel_client_public_key(const char *secret_key, char *out_buf, size_t out_len);

/*
 * Start the in-process tunnel: create the iroh endpoint, optionally bind a
 * loopback SOCKS5 listener, and spawn the connect/auth/serve loop.
 *
 * config_json : NUL-terminated UTF-8 JSON, e.g.
 *   {"server_node_id":"<id>","auth_key":"flextunnelsecretv1:...",
 *    "socks_port":0,"relay_urls":[],"relay_auth_token":null}
 *   auth_key is this client's secret key (from flextunnel_generate_client_key
 *   or `flextunnel generate-auth-private-key`); its public half must be on the
 *   server's authorized_keys_file.
 *   socks_port is optional; null/omitted disables SOCKS5, while 0 requests an
 *   OS-assigned port (read it from the result JSON). relay_auth_token is
 *   optional: a shared bearer token sent to every custom relay's WebSocket
 *   upgrade; it is only valid with custom relay_urls (rejected with the default
 *   iroh relays). The routed set
 *   is configured on the server and pushed to the client during the
 *   handshake, so the app sends no routed set of its own.
 * out_buf/out_len : caller buffer. On success receives {"socks_port":N|null};
 *   on failure receives an error message. Always NUL-terminated. If out_buf is
 *   too small for the success JSON, this is treated as a failure (returns NULL,
 *   no handle leaked) — retry with a larger buffer.
 *
 * Returns a non-NULL handle on success, NULL on failure (including when another
 * instance is already running).
 */
FlextunnelHandle *flextunnel_start(const char *config_json, char *out_buf, size_t out_len);

/*
 * Replace the complete server-direct local-forward set. forwards_json must be a
 * valid NUL-terminated JSON string holding an array of objects:
 *   [{"id":"uuid","local_port":8080,"remote_host":"db.internal",
 *     "remote_port":5432,"enabled":true}]
 *
 * Enabled listeners bind loopback only (127.0.0.1 and ::1). Each accepted TCP
 * connection opens a QUIC data stream directly to the authenticated server;
 * no SOCKS5 proxy is involved. The server enforces its routed-set whitelist and
 * rejects off-list targets.
 *
 * Returns 1 on success, 0 for invalid input, and -1 for a NULL handle.
 * out_buf receives an error message on failure.
 */
int flextunnel_set_forwards(const FlextunnelHandle *handle, const char *forwards_json,
                           char *out_buf, size_t out_len);

/*
 * Snapshot direct-forward states:
 *   {"forwards":[{"id":"uuid","state":"listening","error":null,
 *     "active":1,"last_conn_error":null}]}
 * Returns 1 on success, 0 when out_buf is too small, and -1 for NULL/lock error.
 */
int flextunnel_forward_statuses(const FlextunnelHandle *handle,
                                char *out_buf, size_t out_len);

/*
 * Liveness probe. Returns 1 while the connect/serve loop is running, 0 once it
 * has ended (gave up on a fatal error: bad node id, auth failure, or an
 * unreachable server on the first connect), and -1 for a NULL handle.
 */
int flextunnel_health(const FlextunnelHandle *handle);

/*
 * Snapshot the tunnel's current forwarding set as JSON into out_buf:
 *   {"connected":true,"domains":["*.example.com"],"cidrs":["10.0.0.0/8"],
 *    "host_aliases":[["nas.internal","192.168.1.9"]],
 *    "dns_forwards":[{"suffix":"corp.example.com","servers":["10.1.0.10:5353"]}],
 *    "bridges":[{"name":"lab","endpoint_id":"…","domains":["*.svc"],"cidrs":["fd34::/64"]}]}
 * This is the split-tunnel set the server pushes during the handshake — the
 * domains/CIDRs routed through the tunnel. The local SOCKS proxy owns the split:
 * matching targets use the tunnel, while off-list targets connect directly from
 * the client device. The server independently rejects any off-list request that
 * reaches it. The caller may use the lists for OS routing or display, but does
 * not need to enforce the split itself. Before the first successful handshake,
 * connected is false and the lists are empty. The set becomes available shortly
 * after start once the handshake completes, so poll it. host_aliases ([alias,
 * target] pairs) is informational, for display only — the server resolves the
 * aliases itself. dns_forwards is the
 * server's conditional DNS-forwarding table, also informational: each entry is
 * {"suffix","servers"} — names under suffix resolve via servers instead of the
 * server's system resolver. Empty when none are configured. bridges is the
 * server's outbound bridge-route table (targets it forwards to another
 * flextunnel server), also informational: each entry is
 * {"name","endpoint_id","domains","cidrs"}; the bridged rules are already part
 * of the routed set. Empty when none are configured.
 *
 * Returns 1 on success (full JSON written), 0 if out_buf was too small (the JSON
 * is truncated; retry larger), and -1 for a NULL handle or if the route snapshot
 * could not be read. out_buf is always NUL-terminated when usable (non-NULL,
 * out_len > 0): the error returns write an empty string.
 */
int flextunnel_routes(const FlextunnelHandle *handle, char *out_buf, size_t out_len);

/*
 * Snapshot the live connection's iroh path(s) as JSON into out_buf, mirroring
 * `ezvpn client status`:
 *   {"paths":[
 *     {"kind":"direct","display":"Direct 1.2.3.4:52186 (rtt 1ms)","selected":true},
 *     {"kind":"relay","display":"Relay https://relay.example/ (rtt 42ms)","selected":false}],
 *    "custom_relays":[
 *     {"url":"https://relay.example/","working":true,"error":null}]}
 * A point-in-time snapshot of how the client currently reaches the server,
 * showing ALL discovered paths (not just the selected one). kind is "direct",
 * "relay", or "other" (forward-compatible catch-all); selected marks the path
 * iroh routes over right now. The paths array is EMPTY while disconnected (during
 * a drop/backoff or before the first connect), so only offer this once the tunnel
 * link is up.
 *
 * custom_relays reports each configured custom relay's health from an on-demand
 * GET of its /healthz endpoint (checked in parallel, only when this snapshot is
 * requested). working is true on a 2xx, false when unreachable/timed-out/non-2xx,
 * and null if the check could not run; error carries the failure detail. The
 * array is empty when the default relays are used. /healthz is unauthenticated:
 * it confirms the relay is up, not that a relay_auth_token is accepted.
 *
 * Returns 1 on success (full JSON written), 0 if out_buf was too small (the JSON
 * is truncated; retry larger), and -1 for a NULL handle. out_buf is always
 * NUL-terminated when usable (non-NULL, out_len > 0); the NULL-handle return
 * writes an empty string.
 */
int flextunnel_conn_path(const FlextunnelHandle *handle, char *out_buf, size_t out_len);

/*
 * Stop the proxy and free the handle. After this call the handle is invalid.
 * Passing NULL is a safe no-op.
 */
void flextunnel_stop(FlextunnelHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* FLEXTUNNEL_H */
