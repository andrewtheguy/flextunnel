//! Server-side home-relay watchdog.
//!
//! A server configured with custom relays is reachable to off-LAN clients
//! *only* through its home relay: with n0 discovery off, clients dial with
//! relay hints, and a relay forwards QUIC Initials only to endpoints currently
//! registered on it. iroh keeps that registration alive on its own, but it has
//! been observed (v1.0.3, relays behind Cloudflare tunnels that reset idle
//! WebSockets roughly hourly) to silently lose its home relay for good after
//! one such reset: no dial retries, no warnings, no registration on any relay —
//! the server just stops being dialable until the process is restarted, while
//! LAN clients that find it over mDNS keep working and mask the outage.
//!
//! [`watch_home_relay`] observes [`Endpoint::home_relay_status`] and reacts in
//! two steps, mirroring the client's reconnect escalation:
//!
//! 1. after [`RELAY_OUTAGE_NUDGE`] without a connected home relay it calls
//!    [`Endpoint::network_change`], which forces a fresh net report and relay
//!    re-selection (enough when only the bookkeeping went stale);
//! 2. after the caller's rebuild deadline ([`RELAY_OUTAGE_REBUILD`] by
//!    default) it resolves, telling the caller to replace the endpoint — the
//!    in-process equivalent of the restart that is known to fix it. The caller
//!    (`run_server`) closes the wedged endpoint, binds a fresh one with the
//!    same identity, and serves on again.
//!
//! The resolution also says whether a home relay was connected at *any* point
//! of the watch ([`RelayOutage::relay_seen`]). A rebuilt endpoint that never
//! registers is a sign the relay itself is unreachable, not that iroh's
//! bookkeeping went stale; rebuilding it again drops every LAN client for
//! nothing, so the caller backs off between such rebuilds by passing a longer
//! deadline.
//!
//! Only the *home* relay matters: non-home relays are connected on demand and
//! dropped after a minute idle, which is normal and not an outage.
//!
//! Shared verbatim with ezvpn (`src/transport/relay_watchdog.rs`); keep the two in sync.

use iroh::endpoint::RelayStatus;
use iroh::{Endpoint, Watcher};
use std::future::Future;
use std::time::Duration;
use tokio::time::Instant;

/// How long the endpoint may go without a connected home relay before the
/// watchdog nudges it with `network_change()`. Long enough to ride out a
/// routine relay reconnect (iroh's own reconnect backoff caps at 16s) plus the
/// ~25s cadence of its periodic net report.
pub const RELAY_OUTAGE_NUDGE: Duration = Duration::from_secs(60);

/// Default for how long from the start of the outage before the watchdog
/// gives up on the endpoint and asks for a rebuild. Leaves the nudge two
/// minutes to take effect (a net report through slow relays can take tens of
/// seconds).
pub const RELAY_OUTAGE_REBUILD: Duration = Duration::from_secs(180);

/// A tripped watchdog: the endpoint should be replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayOutage {
    /// How long the endpoint has had no connected home relay.
    pub duration: Duration,
    /// Whether a home relay was connected at any point during the watch.
    /// `false` means this endpoint never registered at all.
    pub relay_seen: bool,
}

/// Watch `endpoint`'s home-relay status and resolve once it has had no
/// connected home relay for `rebuild_after` (at least
/// [`RELAY_OUTAGE_NUDGE`]; [`RELAY_OUTAGE_REBUILD`] is the usual value),
/// having nudged it with `network_change()` at [`RELAY_OUTAGE_NUDGE`]. Never
/// resolves while the home relay stays connected; a reconnect at any point
/// resets the clock. Pending forever once the endpoint is gone.
pub async fn watch_home_relay(endpoint: &Endpoint, rebuild_after: Duration) -> RelayOutage {
    watch_outage(
        endpoint.home_relay_status(),
        |statuses| describe_statuses(statuses),
        || endpoint.network_change(),
        rebuild_after,
    )
    .await
}

/// Describe a home-relay status vector for the watchdog: `Ok(())` when some
/// home relay is connected, otherwise `Err(reason)` naming what is wrong.
fn describe_statuses(statuses: &[RelayStatus]) -> Result<(), String> {
    if statuses.iter().any(RelayStatus::is_connected) {
        return Ok(());
    }
    if statuses.is_empty() {
        return Err("no home relay selected".into());
    }
    let parts: Vec<String> = statuses
        .iter()
        .map(|s| match s.last_error() {
            Some(e) => format!("{} disconnected ({e:#})", s.url()),
            None => format!("{} not connected", s.url()),
        })
        .collect();
    Err(parts.join("; "))
}

/// The watchdog proper, generic over the status source so it can be driven by
/// a plain watchable in tests. `describe` classifies a status value
/// (`Ok` = connected); `nudge` is the first-stage remedy; `rebuild_after` is
/// the outage duration at which the watchdog trips.
async fn watch_outage<W, D, N, Fut>(
    mut watcher: W,
    describe: D,
    mut nudge: N,
    rebuild_after: Duration,
) -> RelayOutage
where
    W: Watcher,
    D: Fn(&W::Value) -> Result<(), String>,
    N: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    let rebuild_after = rebuild_after.max(RELAY_OUTAGE_NUDGE);
    let mut outage_since: Option<Instant> = None;
    let mut nudged = false;
    let mut relay_seen = false;
    let mut value = watcher.get();
    loop {
        match describe(&value) {
            Ok(()) => {
                relay_seen = true;
                if let Some(since) = outage_since.take() {
                    log::info!(
                        "Home relay connection restored after {:.0}s",
                        since.elapsed().as_secs_f64()
                    );
                }
                nudged = false;
            }
            Err(reason) => {
                if outage_since.is_none() {
                    outage_since = Some(Instant::now());
                    log::warn!(
                        "No connected home relay ({reason}); off-LAN clients cannot reach this \
                         server until it reconnects"
                    );
                }
            }
        }

        let Some(since) = outage_since else {
            // Healthy: nothing to time, just wait for the next status change.
            value = match watcher.updated().await {
                Ok(value) => value,
                Err(_disconnected) => std::future::pending().await,
            };
            continue;
        };

        let deadline = since
            + if nudged {
                rebuild_after
            } else {
                RELAY_OUTAGE_NUDGE
            };
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                if nudged {
                    return RelayOutage {
                        duration: since.elapsed(),
                        relay_seen,
                    };
                }
                nudged = true;
                log::warn!(
                    "Still no connected home relay after {:.0}s; nudging the endpoint to \
                     re-check its network and relays",
                    since.elapsed().as_secs_f64()
                );
                nudge().await;
                // The nudge may have already reconnected the relay; re-read
                // rather than wait for a change notification we may have
                // missed while it ran.
                value = watcher.get();
            }
            updated = watcher.updated() => {
                value = match updated {
                    Ok(value) => value,
                    Err(_disconnected) => std::future::pending().await,
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use n0_watcher::Watchable;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test double for the home-relay status: `true` = a home relay is
    /// connected.
    fn describe(connected: &bool) -> Result<(), String> {
        if *connected {
            Ok(())
        } else {
            Err("down".into())
        }
    }

    /// Run the watchdog on `status` with the default rebuild deadline,
    /// counting nudges. Returns the watchdog future's resolution wrapped in a
    /// bounded wait so a test never hangs.
    async fn run_for(
        status: &Watchable<bool>,
        nudges: Arc<AtomicUsize>,
        bound: Duration,
    ) -> Option<RelayOutage> {
        run_with_deadline(status, nudges, bound, RELAY_OUTAGE_REBUILD).await
    }

    async fn run_with_deadline(
        status: &Watchable<bool>,
        nudges: Arc<AtomicUsize>,
        bound: Duration,
        rebuild_after: Duration,
    ) -> Option<RelayOutage> {
        let watchdog = watch_outage(
            status.watch(),
            describe,
            || {
                let nudges = nudges.clone();
                async move {
                    nudges.fetch_add(1, Ordering::SeqCst);
                }
            },
            rebuild_after,
        );
        tokio::time::timeout(bound, watchdog).await.ok()
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_relay_never_trips() {
        let status = Watchable::new(true);
        let nudges = Arc::new(AtomicUsize::new(0));
        let tripped = run_for(&status, nudges.clone(), RELAY_OUTAGE_REBUILD * 3).await;
        assert!(
            tripped.is_none(),
            "healthy relay must never request a rebuild"
        );
        assert_eq!(nudges.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn sustained_outage_nudges_then_requests_rebuild() {
        let status = Watchable::new(false);
        let nudges = Arc::new(AtomicUsize::new(0));
        let outage = run_for(&status, nudges.clone(), RELAY_OUTAGE_REBUILD * 2)
            .await
            .expect("a sustained outage must request a rebuild");
        assert_eq!(
            nudges.load(Ordering::SeqCst),
            1,
            "exactly one nudge before the rebuild"
        );
        assert!(outage.duration >= RELAY_OUTAGE_REBUILD);
        assert!(outage.duration < RELAY_OUTAGE_REBUILD + Duration::from_secs(1));
        assert!(
            !outage.relay_seen,
            "a relay that was never connected must be reported as never seen"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_longer_rebuild_deadline_delays_the_trip_but_not_the_nudge() {
        let status = Watchable::new(false);
        let nudges = Arc::new(AtomicUsize::new(0));
        let rebuild_after = RELAY_OUTAGE_REBUILD * 4;
        let nudge_count = nudges.clone();
        let (outage, ()) = tokio::join!(
            run_with_deadline(&status, nudges.clone(), rebuild_after * 2, rebuild_after),
            async move {
                // The nudge still comes at the fixed first-stage deadline.
                tokio::time::sleep(RELAY_OUTAGE_NUDGE + Duration::from_secs(1)).await;
                assert_eq!(nudge_count.load(Ordering::SeqCst), 1);
            }
        );
        let outage = outage.expect("a sustained outage must request a rebuild");
        assert!(outage.duration >= rebuild_after);
        assert!(outage.duration < rebuild_after + Duration::from_secs(1));
        assert_eq!(nudges.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_before_the_nudge_resets_the_clock() {
        let status = Watchable::new(true);
        let nudges = Arc::new(AtomicUsize::new(0));
        let flipper = {
            let status = status.clone();
            async move {
                // Drop out for half the nudge window, then recover; the
                // watchdog must neither nudge nor trip.
                tokio::time::sleep(Duration::from_secs(5)).await;
                status.set(false).ok();
                tokio::time::sleep(RELAY_OUTAGE_NUDGE / 2).await;
                status.set(true).ok();
            }
        };
        let (tripped, ()) = tokio::join!(
            run_for(&status, nudges.clone(), RELAY_OUTAGE_REBUILD * 2),
            flipper
        );
        assert!(tripped.is_none());
        assert_eq!(nudges.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn recovery_after_the_nudge_avoids_the_rebuild() {
        let status = Watchable::new(false);
        let nudges = Arc::new(AtomicUsize::new(0));
        let flipper = {
            let status = status.clone();
            async move {
                // Recover between the nudge and the rebuild deadline.
                tokio::time::sleep(RELAY_OUTAGE_NUDGE + Duration::from_secs(10)).await;
                status.set(true).ok();
            }
        };
        let (tripped, ()) = tokio::join!(
            run_for(&status, nudges.clone(), RELAY_OUTAGE_REBUILD * 2),
            flipper
        );
        assert!(
            tripped.is_none(),
            "a relay that came back must not be rebuilt"
        );
        assert_eq!(nudges.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_outage_starts_a_fresh_clock() {
        let status = Watchable::new(false);
        let nudges = Arc::new(AtomicUsize::new(0));
        let flipper = {
            let status = status.clone();
            async move {
                // First outage: nudged, then recovers. Second outage: must
                // get its own nudge and only trip a full window later.
                tokio::time::sleep(RELAY_OUTAGE_NUDGE + Duration::from_secs(10)).await;
                status.set(true).ok();
                tokio::time::sleep(Duration::from_secs(10)).await;
                status.set(false).ok();
            }
        };
        let start = Instant::now();
        let (tripped, ()) = tokio::join!(
            run_for(&status, nudges.clone(), RELAY_OUTAGE_REBUILD * 3),
            flipper
        );
        let outage = tripped.expect("second outage must eventually trip");
        assert_eq!(nudges.load(Ordering::SeqCst), 2);
        assert!(outage.duration >= RELAY_OUTAGE_REBUILD);
        assert!(outage.duration < RELAY_OUTAGE_REBUILD + Duration::from_secs(1));
        assert!(
            outage.relay_seen,
            "the relay was connected between the outages, so it was seen"
        );
        // Second outage began at nudge + 20s; the trip comes a full window after that.
        let total = start.elapsed();
        assert!(total >= RELAY_OUTAGE_NUDGE + Duration::from_secs(20) + RELAY_OUTAGE_REBUILD);
    }
}
