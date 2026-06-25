#!/bin/sh
# =============================================================================
# Q-Periapt camera-ready bare-metal experiments — ONE turnkey command.
#
# Run this on a QUIESCED bare-metal x86_64 Linux host (NOT a VM, NOT emulated):
#
#     sudo sh camera-ready-bare-metal.sh 2>&1 | tee camera-ready.txt
#
# then paste camera-ready.txt back. It produces the two numbers the paper defers
# to bare metal:
#   (1) netem time-to-session p50, 4 groups (classical / X25519MLKEM768 standard /
#       ContextBound / CompatXWing), REPS=20 per RTT — the per-group latency the
#       reviewers asked for (our virtualized host was too noisy to publish).
#   (2) the source->binary constant-time discriminator, NATIVELY (real Memcheck
#       timing, not qemu) — ML-KEM probe=0 (clean) vs HQC prefix>0 (leaky).
#
# Prereqs: Rust toolchain (rustup), root (tc needs NET_ADMIN), Docker (for the CT
# probe's pinned container). Each section degrades gracefully if a prereq is absent.
# =============================================================================
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
echo "================ Q-Periapt camera-ready bare-metal ================"
echo "host: $(uname -srm)   date: $(date -u +%Y-%m-%dT%H:%MZ)"
echo "cpu : $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/.*: //' || sysctl -n machdep.cpu.brand_string 2>/dev/null || echo '?')"
echo

# ---- (1) netem 4-group latency, REPS=20 -------------------------------------
echo "######## (1) netem time-to-session, 4 groups, REPS=20 ########"
if [ "$(id -u)" != 0 ]; then
  echo "SKIP: not root — re-run with sudo for the tc netem section."
elif ! command -v tc >/dev/null 2>&1; then
  echo "SKIP: 'tc' not found (install iproute2)."
else
  REPS=20 sh paper/netem-camera-ready.sh || echo "(netem section returned non-zero)"
fi
echo

# ---- (2) native source->binary CT discriminator -----------------------------
echo "######## (2) source->binary CT discriminator (NATIVE Memcheck) ########"
if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker not found. Native fallback (needs valgrind + cargo):"
  if command -v valgrind >/dev/null 2>&1 && command -v cargo >/dev/null 2>&1; then
    export CARGO_TARGET_DIR=/tmp/ctbuild
    cargo build --release -p q-periapt-ctstats --bin ct_decaps_gap --features valgrind 2>/dev/null \
      && cargo build --release -p q-periapt-ctstats --bin ct_hqc_gap --features valgrind,hqc 2>/dev/null
    B=/tmp/ctbuild/release
    for m in control ek wholedk probe; do
      valgrind --leak-check=no --track-origins=yes "$B/ct_decaps_gap" "$m" >/tmp/o.$m 2>&1 || true
      printf '  ml-kem %-8s %s\n' "$m" "$(grep 'ERROR SUMMARY' /tmp/o.$m | tail -1 | sed 's/^==[0-9]*== //')"
    done
    valgrind --leak-check=no --track-origins=yes "$B/ct_hqc_gap" prefix >/tmp/o.hqc 2>&1 || true
    printf '  hqc    %-8s %s\n' prefix "$(grep 'ERROR SUMMARY' /tmp/o.hqc | tail -1 | sed 's/^==[0-9]*== //')"
  else
    echo "SKIP: neither docker nor (valgrind+cargo) available."
  fi
else
  sh ctstats/scripts/ct-gap-probe.sh || echo "(CT probe returned non-zero)"
fi
echo
echo "================ done — paste this whole transcript back ================"
