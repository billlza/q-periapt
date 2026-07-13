#!/usr/bin/env sh
# Binary dataflow probe: run the shipped fips203-backed ML-KEM-768 wrapper under Memcheck while
# marking only the genuine secret (ŝ + z). This is an empirical check of this build and target,
# not a source-level proof or a claim inherited from the former backend.
#
#   sh ctstats/scripts/ct-gap-probe.sh                                   # native container arch
#   DOCKER_DEFAULT_PLATFORM=linux/amd64 sh ctstats/scripts/ct-gap-probe.sh   # x86_64 (emulated on ARM)
#
# Reports, per arch: a planted-secret control (MUST be caught, else the probe is vacuous), then
# summaries for whole-dk and ek-only (diagnostics with no fixed expected count), and probe
# (ŝ+z — the actual gate, which MUST report zero).
set -eu

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
if [ -n "${DOCKER_DEFAULT_PLATFORM:-}" ]; then
  set -- --platform "$DOCKER_DEFAULT_PLATFORM"
else
  set --
fi

exec docker run --rm "$@" -v "$REPO_ROOT":/work:ro -w /work rust:slim sh -c '
  set -e
  echo "=== shipped-backend binary dataflow probe; container arch: $(uname -m) ==="
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq valgrind build-essential >/dev/null 2>&1
  valgrind --version
  export CARGO_TARGET_DIR=/tmp/ctbuild
  export CARGO_TERM_COLOR=never
  export RUSTFLAGS=-Dwarnings
  cargo build --release -p q-periapt-ctstats --bin ct_decaps_gap --features valgrind
  BIN=/tmp/ctbuild/release/ct_decaps_gap

  # Harness control: only the dedicated Valgrind error sentinel is accepted.
  # A tool failure, crash, or unrelated process exit must not masquerade as a caught leak.
  set +e
  valgrind --error-exitcode=99 --leak-check=no --track-origins=yes \
    "$BIN" control >/tmp/out.control 2>&1
  control_rc=$?
  set -e
  if [ "$control_rc" -ne 99 ] || ! grep -Eq "ERROR SUMMARY: [1-9][0-9]* errors" /tmp/out.control; then
    cat /tmp/out.control
    echo "CONTROL FAILED on $(uname -m): expected Valgrind sentinel 99 and a positive error summary, got rc=$control_rc"
    exit 2
  fi
  controln=$(grep "ERROR SUMMARY" /tmp/out.control | tail -1 | grep -oE "[0-9]+ errors" | grep -oE "^[0-9]+")
  echo "control OK: Memcheck catches a planted secret-dependent access on $(uname -m) ($controln errors)"
  echo

  run() {
    valgrind --leak-check=no --track-origins=yes "$BIN" "$1" >/tmp/out."$1" 2>&1
    summary=$(grep "ERROR SUMMARY" /tmp/out."$1" | tail -1 | sed "s/^==[0-9]*== //")
    printf "  %-8s %s\n" "$1:" "$summary"
  }
  echo "Memcheck summaries for the shipped fips203-backed q-periapt wrapper:"
  run wholedk   # diagnostic: all 2400 dk bytes; zero or non-zero is backend/build dependent
  run ek        # diagnostic: embedded public ek; zero or non-zero is not a gate
  run probe     # gate: ŝ[0..1152]+z[2368..2400] MUST report zero
  echo
  echo "interpretation: probe = 0 errors means this optimized wrapper binary emitted no"
  echo "                Memcheck-visible secret-dependent branch/index on the exercised ŝ/z paths."
  echo "                ek/wholedk are diagnostics only; no fixed non-zero count is required."

  # DISCRIMINATOR: a separate, dependency-free binary with an explicit planted secret branch.
  # If this were also 0 the probe would be vacuous; >0 proves the harness distinguishes the
  # production ML-KEM path from deliberately leaky code without retaining a vulnerable backend.
  echo
  echo "=== discriminator: synthetic planted secret-dependent branch ==="
  cargo build --release -p q-periapt-ctstats --bin ct_leaky_control --features valgrind
  LEAKY_BIN=/tmp/ctbuild/release/ct_leaky_control
  set +e
  valgrind --error-exitcode=99 --leak-check=no --track-origins=yes \
    "$LEAKY_BIN" planted >/tmp/out.leaky-control 2>&1
  leaky_rc=$?
  set -e
  if [ "$leaky_rc" -ne 99 ] || ! grep -Eq "ERROR SUMMARY: [1-9][0-9]* errors" /tmp/out.leaky-control; then
    cat /tmp/out.leaky-control
    echo "LEAKY CONTROL FAILED on $(uname -m): expected Valgrind sentinel 99 and a positive error summary, got rc=$leaky_rc"
    exit 3
  fi
  leakysum=$(grep "ERROR SUMMARY" /tmp/out.leaky-control | tail -1 | sed "s/^==[0-9]*== //")
  printf "  %-16s %s\n" "leaky-control:" "$leakysum"
  mlkemn=$(grep "ERROR SUMMARY" /tmp/out.probe | tail -1 | grep -oE "[0-9]+ errors" | grep -oE "^[0-9]+")
  leakyn=$(grep "ERROR SUMMARY" /tmp/out.leaky-control | tail -1 | grep -oE "[0-9]+ errors" | grep -oE "^[0-9]+")
  echo
  if [ "${mlkemn:-1}" = "0" ] && [ "${leakyn:-0}" -gt 0 ] 2>/dev/null; then
    echo "DISCRIMINATOR HOLDS on $(uname -m): ML-KEM probe = 0 vs planted secret branch = $leakyn."
  else
    echo "DISCRIMINATOR CHECK on $(uname -m): ML-KEM=${mlkemn:-?}, planted=${leakyn:-?} (expected 0 vs >0)."
    exit 3
  fi
'
