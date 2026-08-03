# Roadmap: duplicate-id detection

Status: the **current** duplicate-id detection is implemented (see
[`architecture.md`](./architecture.md) → "Duplicate-id detection"). This document
records the deliberate limitations and the future work around them.

## 1. Non-ephemeral client id — future use case & pitfalls (gotcha)

Today the client's iroh identity is **ephemeral**: a fresh random key per
process (`create_client_endpoint` binds with no secret). This is what makes
duplicate-*client* detection simple and safe:

- Two *different* client processes never collide on a node id, so a node id seen
  on two concurrently-live connections is a **very unlikely bug**.
- Because an ephemeral id never recurs, the server can **block any duplicate id it
  encounters** with zero risk of harming a legitimate future client — the blocked
  id is gone forever anyway. The persisted client entry is mostly an audit record.

If clients ever gain a **persistent** identity (a secret-key file, like the
server — e.g. to let the server authorize specific clients, or for stable
observability), this simplicity breaks and the design must change:

- **Blocking a persistent client id would lock out the legitimate client** until
  an operator clears the blocklist. Auto-blocking on detection becomes an
  availability footgun, exactly as it is for the server today.
- **Duplicates become plausible, not rare** — copying a client config (secret +
  token) to a second device is an easy misconfiguration, so detection would fire
  in normal-ish operations rather than only on a genuine bug.
- It would need **identity vs credential separation** (node id, auth token, and a
  human-facing client name are three different things), an **operator-clearable,
  per-client** blocklist with clear provenance, and likely a softer first
  response (warn / disconnect-newcomer) before any sticky block.

Net: the current "block whatever duplicate you see" rule is correct **only**
under ephemeral client ids. Revisit all of the above before introducing
persistent client identity.

## 2. Server-dup detection: scope & the signaling-server limitation

Scope first: a *duplicate server id* is only a conflict when both same-id servers
are reachable by the **same client over a shared discovery/relay path**. Same-id
servers on isolated networks that no single client can reach both of (e.g.
LAN-only path in different LANs, no shared relay/DNS) are **not a duplicate-id
situation** and are not addressed here — there is nothing to detect and no
signaling server would be relevant.

Within the in-scope shared-path case, the current detection (server-nonce
reappearance observed by a client → advisory → server self-block) is:

- **Delayed and churn-dependent.** A client only observes the second instance if
  connection instability/path changes actually bounce it between the two servers.
  A client pinned to one instance never sees the other.
- **Post-hoc.** Nothing catches the conflict *before* client traffic exercises it.

A **signaling server** (or any shared rendezvous both servers publish to) would
make this prompt and reliable: each server registers a liveness lease under its
`EndpointId`, and a second registration for the same id is detected directly —
even with no client traffic and regardless of client path affinity. Adding one is
the natural next step if prompt server-dup detection is required. iroh's own
pkarr/DNS publishing is a candidate substrate (a server could watch for a second
live publisher of its own id), with the usual caveats (relay-only addresses, NAT,
record TTLs).

## 3. Client-side id-dup acknowledgement / flagging (future)

Today the client that detects a duplicate server **advises** the server (which
self-blocks) and logs a warning, but keeps no durable record of its own. Future
work:

- **Persist the observation** across client restarts (a small state file), so a
  client that has seen a duplicate server can refuse or warn immediately on the
  next launch instead of re-deriving it from scratch.
- **Surface a user-visible flag** through the CLI and the desktop app (a status
  field alongside `TunnelRoutes`), so the app can show "duplicate server id
  detected" to the operator.
- **Client-side acknowledgement** of a duplicate *client* id, which only becomes
  meaningful once clients have persistent ids (§1) — the client could then flag
  that its own identity was involved in a conflict.

These are additive: none change the wire protocol's current duplicate-detection
semantics, they extend persistence and surfacing on the client side.
