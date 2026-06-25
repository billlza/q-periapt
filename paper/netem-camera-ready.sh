#!/bin/sh
# Camera-ready netem P99 for the Q-Periapt TLS 1.3 handshake (paper Fig. "netem").
# Run on a QUIESCED BARE-METAL Linux host (root needed for tc; Rust toolchain needed).
# Reproduces: classical X25519 vs ContextBound vs CompatXWing time-to-session under real netem.
set -eu
[ "$(id -u)" = 0 ] || { echo "run as root (tc needs NET_ADMIN)"; exit 1; }
REPS=${REPS:-5}
cargo build --release -p q-periapt-rustls --example netem_bench
BIN=target/release/examples/netem_bench
run() { # one_way_ms iters
  tc qdisc del dev lo root 2>/dev/null || true
  [ "$1" != 0 ] && tc qdisc add dev lo root netem delay "$1"ms
  echo "== one-way=$1 ms (RTT=$(( $1 * 2 )) ms), $REPS reps =="
  i=1; while [ "$i" -le "$REPS" ]; do
    for k in classical standard bound compat; do
      printf 'rep%s %-10s ' "$i" "$k"; "$BIN" "$k" "$2" 100 | grep p50
    done; i=$(( i + 1 ))
  done
  tc qdisc del dev lo root 2>/dev/null || true
}
run 0 2000
run 10 800
run 25 600
echo 'Done. Report mean p50 + run-to-run spread per (RTT, group); RTT>=20ms overhead is within noise.'
