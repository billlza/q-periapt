#!/bin/sh
# =============================================================================
# Q-Periapt camera-ready bare-metal experiments — ONE turnkey command.
#
#     sudo sh camera-ready-bare-metal.sh 2>&1 | tee camera-ready.txt
#
# Run on a QUIESCED bare-metal x86_64 Linux host (NOT a VM, NOT emulated). Produces the
# two numbers the paper defers to bare metal, with variance pinned down:
#   (1) netem time-to-session p50, 4 groups (classical / X25519MLKEM768 standard /
#       ContextBound / CompatXWing), REPS=20 per RTT, bench PINNED to dedicated cores.
#   (2) the source->binary constant-time discriminator, NATIVELY (real Memcheck timing):
#       ML-KEM probe=0 (clean) vs HQC prefix>0 (leaky).
#
# Variance control (the whole point): performance governor + boost OFF + taskset pinning.
# On a 7950X3D the default PIN=4-5 sits on one CCD so client+server don't cross CCDs.
# Override with:  PIN=12-13 REPS=30 sudo -E sh camera-ready-bare-metal.sh
#
# Prereqs: Rust (cargo on PATH), root (tc + tuning), and EITHER docker OR (valgrind+cargo)
# for section (2). Each section degrades gracefully if a prereq is missing.
# =============================================================================
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd); cd "$ROOT"
PIN="${PIN:-4-5}"      # cores for the bench (client+server); keep on ONE CCD
REPS="${REPS:-20}"
ISROOT=0; [ "$(id -u)" = 0 ] && ISROOT=1

echo "================ Q-Periapt camera-ready bare-metal ================"
echo "host : $(uname -srm)    date: $(date -u +%Y-%m-%dT%H:%MZ)"
echo "cpu  : $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //')"
echo "pin  : cores $PIN   reps: $REPS   root: $ISROOT"
echo

# ---- variance control (best-effort; remembers prior state to restore) -------
GOV_OLD=""; BOOST_PATH=""; BOOST_OLD=""
tune() {
  [ "$ISROOT" = 1 ] || { echo "(not root — skipping governor/boost tuning)"; return; }
  GOV_OLD=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "")
  for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$g" 2>/dev/null || true; done
  if [ -f /sys/devices/system/cpu/cpufreq/boost ]; then            # AMD
    BOOST_PATH=/sys/devices/system/cpu/cpufreq/boost; BOOST_OLD=$(cat "$BOOST_PATH"); echo 0 > "$BOOST_PATH" 2>/dev/null || true
  elif [ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]; then  # Intel
    BOOST_PATH=/sys/devices/system/cpu/intel_pstate/no_turbo; BOOST_OLD=$(cat "$BOOST_PATH"); echo 1 > "$BOOST_PATH" 2>/dev/null || true
  fi
  echo "tuning: governor=performance (was '${GOV_OLD:-?}'), boost/turbo disabled ($BOOST_PATH)"
  # the bench opens a fresh TCP conn per handshake (tens of thousands total); without these,
  # TIME_WAIT/port pressure injects ~100ms connect stalls into later reps. Standard harness fix.
  sysctl -w net.ipv4.tcp_tw_reuse=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.ip_local_port_range="1024 65535" >/dev/null 2>&1 || true
  sysctl -w net.ipv4.tcp_fin_timeout=3 >/dev/null 2>&1 || true   # drain TIME_WAIT fast (paced reps keep it tiny)
  echo "tuning: tcp_tw_reuse=1, port_range widened, fin_timeout=3 (loopback churn)"
}
restore() {
  [ -n "$GOV_OLD" ] && for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo "$GOV_OLD" > "$g" 2>/dev/null || true; done
  [ -n "$BOOST_PATH" ] && echo "$BOOST_OLD" > "$BOOST_PATH" 2>/dev/null || true
}
trap restore EXIT INT TERM
tune; echo

# ---- build the bench --------------------------------------------------------
if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
echo "building netem_bench (release)..."
cargo build --release -p q-periapt-rustls --example netem_bench >/tmp/build.log 2>&1 \
  || { echo "BUILD FAILED — see below"; tail -20 /tmp/build.log; exit 1; }
BIN=target/release/examples/netem_bench
PINCMD=""; command -v taskset >/dev/null 2>&1 && PINCMD="taskset -c $PIN"

# ---- (1) netem 4-group latency, REPS, pinned --------------------------------
echo
echo "######## (1) netem time-to-session, 4 groups, REPS=$REPS, pinned to cores $PIN ########"
if [ "$ISROOT" != 1 ]; then
  echo "SKIP: not root (tc netem needs NET_ADMIN). Re-run with sudo -E."
elif ! command -v tc >/dev/null 2>&1; then
  echo "SKIP: 'tc' not found — apt-get install -y iproute2"
else
  netrun() { # one_way_ms iters reps
    tc qdisc del dev lo root 2>/dev/null || true
    [ "$1" != 0 ] && tc qdisc add dev lo root netem delay "$1"ms
    echo "== one-way=$1 ms (RTT=$(( $1 * 2 )) ms), reps=$3 =="
    i=1; while [ "$i" -le "$3" ]; do
      for k in classical standard bound compat; do
        printf 'rep%-2s %-10s ' "$i" "$k"; $PINCMD "$BIN" "$k" "$2" 100 | grep p50
      done; i=$(( i + 1 ))
      sleep 2   # let TIME_WAIT drain between reps so loopback churn never stalls connect()
    done
    tc qdisc del dev lo root 2>/dev/null || true
  }
  netrun 0  300 "$REPS"    # RTT~0: the noise-sensitive CPU comparison (was unpublishable on the VM) — FULL reps
  netrun 10 250 6          # RTT=20ms: confirmatory (RTT dominates variance) — few reps, fewer iters
  netrun 25 150 4          # RTT=50ms: confirmatory
  echo "report: per (RTT,group) take median p50 + run-to-run spread; RTT>=20ms overhead is within noise."
fi

# ---- (2) native source->binary CT discriminator -----------------------------
echo
echo "######## (2) source->binary CT discriminator (NATIVE Memcheck) ########"
if command -v docker >/dev/null 2>&1; then
  sh ctstats/scripts/ct-gap-probe.sh || echo "(CT probe via docker returned non-zero)"
elif command -v valgrind >/dev/null 2>&1; then
  export CARGO_TARGET_DIR=/tmp/ctbuild
  cargo build --release -p q-periapt-ctstats --bin ct_decaps_gap --features valgrind >/dev/null 2>&1 \
    && cargo build --release -p q-periapt-ctstats --bin ct_hqc_gap --features valgrind,hqc >/dev/null 2>&1
  B=/tmp/ctbuild/release
  if valgrind --error-exitcode=1 --leak-check=no -q "$B/ct_decaps_gap" control >/dev/null 2>&1; then
    echo "NEGATIVE CONTROL FAILED: planted leak not caught — probe vacuous"; else echo "negative control OK"; fi
  for m in ek wholedk probe; do
    valgrind --leak-check=no --track-origins=yes "$B/ct_decaps_gap" "$m" >/tmp/o.$m 2>&1 || true
    printf '  ml-kem %-8s %s\n' "$m" "$(grep 'ERROR SUMMARY' /tmp/o.$m | tail -1 | sed 's/^==[0-9]*== //')"
  done
  valgrind --leak-check=no --track-origins=yes "$B/ct_hqc_gap" prefix >/tmp/o.hqc 2>&1 || true
  printf '  hqc    %-8s %s\n' prefix "$(grep 'ERROR SUMMARY' /tmp/o.hqc | tail -1 | sed 's/^==[0-9]*== //')"
  echo "discriminator: expect ML-KEM probe = 0 (clean) vs HQC prefix > 0 (leaky)."
else
  echo "SKIP: neither docker nor valgrind found — apt-get install -y valgrind"
fi
echo
echo "================ done — paste this whole transcript back ================"
