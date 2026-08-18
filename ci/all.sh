#!/usr/bin/env bash
# Run the whole of .github/workflows/ci.yml locally, across the three machines
# that stand in for its three runners. The platform this script runs on is done
# natively (ci/unix/ci.sh picks its own platform's steps); the other two go
# over ssh:
#
#   mac      natively on a Mac, else the FLEXTUNNEL_MACCI_HOST alias
#            (default 'macwork')                ci/unix/{ci,remote}.sh
#   linux    natively on Linux, else the FLEXTUNNEL_UNIXCI_HOST alias
#            (default 'workstation-wsl')        ci/unix/{ci,remote}.sh
#   windows  the FLEXTUNNEL_WINCI_HOST alias
#            (default 'winsandbox')             ci/windows/remote.sh
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

native=$(uname -s)

run_job() {
    case $1 in
        mac)
            if [ "$native" = Darwin ]; then ./ci/unix/ci.sh
            else ./ci/unix/remote.sh -H "${FLEXTUNNEL_MACCI_HOST:-macwork}" ci; fi ;;
        linux)
            if [ "$native" = Linux ]; then ./ci/unix/ci.sh
            else ./ci/unix/remote.sh ci; fi ;;
        windows) ./ci/windows/remote.sh ci ;;
    esac
}

# A full template rather than -t: BSD and GNU mktemp disagree on what -t means.
logdir=$(mktemp -d "${TMPDIR:-/tmp}/flextunnel-ci.XXXXXX")
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
