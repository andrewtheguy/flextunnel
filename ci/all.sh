#!/usr/bin/env bash
# Run the whole of .github/workflows/ci.yml locally, across the three machines
# that stand in for its three runners:
#
#   mac      this machine, natively            ci/unix/ci.sh
#   linux    the 'workstation-wsl' ssh alias   ci/unix/remote.sh
#   windows  the 'winsandbox' ssh alias        ci/windows/remote.sh
#
#   ci/all.sh                  # all three
#   ci/all.sh linux windows    # only these
#
# The three run concurrently — they are three different machines, and the only
# thing they share is this one's upload bandwidth. That means their output would
# interleave into nonsense, so each one's log is captured and replayed in full,
# in order, once everything has finished; a summary of exit codes comes last.
# To watch a single platform live, run its script directly.
set -uo pipefail

cd "$(dirname "$0")/.."

usage() { echo "usage: $0 [mac|linux|windows ...]" >&2; exit 2; }

jobs=("$@")
[ ${#jobs[@]} -eq 0 ] && jobs=(mac linux windows)
for job in "${jobs[@]}"; do
    case $job in mac|linux|windows) ;; *) usage ;; esac
done

run_job() {
    case $1 in
        mac)     ./ci/unix/ci.sh ;;
        linux)   ./ci/unix/remote.sh ci ;;
        windows) ./ci/windows/remote.sh ci ;;
    esac
}

logdir=$(mktemp -d -t flextunnel-ci)
trap 'rm -rf "$logdir"' EXIT

echo "[ci] starting: ${jobs[*]}"
pids=()
for job in "${jobs[@]}"; do
    run_job "$job" >"$logdir/$job.log" 2>&1 &
    pids+=($!)
done

status=()
for i in "${!jobs[@]}"; do
    wait "${pids[$i]}"
    status+=($?)
done

failed=0
for i in "${!jobs[@]}"; do
    echo ''
    echo "############################################################"
    echo "# ${jobs[$i]} (exit ${status[$i]})"
    echo "############################################################"
    cat "$logdir/${jobs[$i]}.log"
    [ "${status[$i]}" -eq 0 ] || failed=1
done

echo ''
echo '== summary =='
for i in "${!jobs[@]}"; do
    if [ "${status[$i]}" -eq 0 ]; then
        printf '  %-8s ok\n' "${jobs[$i]}"
    else
        printf '  %-8s FAILED (exit %s)\n' "${jobs[$i]}" "${status[$i]}"
    fi
done

exit $failed
