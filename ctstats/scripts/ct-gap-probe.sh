#!/usr/bin/env sh
# Source→binary CT gap probe: run real libcrux ML-KEM-768 `decapsulate` under Memcheck while
# marking ONLY the genuine secret (ŝ + z), to test whether the compiler reintroduces a
# secret-dependent branch despite libcrux's source-level secret-independence.
#
#   sh ctstats/scripts/ct-gap-probe.sh                                   # native container arch
#   DOCKER_DEFAULT_PLATFORM=linux/amd64 sh ctstats/scripts/ct-gap-probe.sh   # x86_64 (emulated on ARM)
#
# Reports, per arch: a negative-control check (a planted secret branch MUST be caught, else the
# probe is vacuous), then the Memcheck error summary for whole-dk (baseline), ek-only
# (attribution), and probe (ŝ+z — the actual gap question; 0 = source-CT survived compilation).
set -eu

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
if [ -n "${DOCKER_DEFAULT_PLATFORM:-}" ]; then
  set -- --platform "$DOCKER_DEFAULT_PLATFORM"
else
  set --
fi

exec docker run --rm "$@" -v "$REPO_ROOT":/work:ro -w /work rust:slim sh -c '
  set -e
  echo "=== source->binary CT gap probe; container arch: $(uname -m) ==="
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq valgrind build-essential >/dev/null 2>&1
  valgrind --version
  export CARGO_TARGET_DIR=/tmp/ctbuild
  export CARGO_TERM_COLOR=never
  export RUSTFLAGS=-Dwarnings
  cargo build --release -p q-periapt-ctstats --bin ct_decaps_gap --features valgrind
  BIN=/tmp/ctbuild/release/ct_decaps_gap

  # Negative control: a deliberate secret-dependent branch MUST produce a positive summary.
  valgrind --leak-check=no --track-origins=yes "$BIN" control >/tmp/out.control 2>&1
  controln=$(grep "ERROR SUMMARY" /tmp/out.control | tail -1 | grep -oE "[0-9]+ errors" | grep -oE "^[0-9]+")
  if [ "$controln" -le 0 ]; then
    echo "NEGATIVE CONTROL FAILED on $(uname -m): planted secret branch NOT caught — probe vacuous"
    exit 2
  fi
  echo "negative control OK: Memcheck catches a planted secret branch on $(uname -m) ($controln errors)"
  echo

  run() {
    valgrind --leak-check=no --track-origins=yes "$BIN" "$1" >/tmp/out."$1" 2>&1
    summary=$(grep "ERROR SUMMARY" /tmp/out."$1" | tail -1 | sed "s/^==[0-9]*== //")
    printf "  %-8s %s\n" "$1:" "$summary"
  }
  echo "Memcheck error summaries (marking the named field(s) secret, real libcrux decapsulate):"
  run wholedk   # all 2400 dk bytes  -> baseline (~5696 errors / 60 contexts, on embedded ek)
  run ek        # ek[1152..2336]     -> attribution (the ~60 q-branches are on the PUBLIC key)
  run probe     # ŝ[0..1152]+z[2368..2400] -> THE GAP QUESTION (0 = no source->binary gap)
  echo
  echo "interpretation: probe = 0 errors  => libcrux ML-KEM decaps secret-independence survives"
  echo "                compilation on $(uname -m) (no source->binary CT gap on the ŝ/z path)."

  # DISCRIMINATOR: a separate, dependency-free binary with an explicit planted secret branch.
  # If this were also 0 the probe would be vacuous; >0 proves the harness distinguishes the
  # production ML-KEM path from deliberately leaky code without retaining a vulnerable backend.
  echo
  echo "=== discriminator: synthetic planted secret-dependent branch ==="
  cargo build --release -p q-periapt-ctstats --bin ct_leaky_control --features valgrind
  LEAKY_BIN=/tmp/ctbuild/release/ct_leaky_control
  valgrind --leak-check=no --track-origins=yes "$LEAKY_BIN" planted >/tmp/out.leaky-control 2>&1
  leakysum=$(grep "ERROR SUMMARY" /tmp/out.leaky-control | tail -1 | sed "s/^==[0-9]*== //")
  printf "  %-16s %s\n" "leaky-control:" "$leakysum"
  mlkemn=$(grep "ERROR SUMMARY" /tmp/out.probe | tail -1 | grep -oE "[0-9]+ errors" | grep -oE "^[0-9]+")
  leakyn=$(grep "ERROR SUMMARY" /tmp/out.leaky-control | tail -1 | grep -oE "[0-9]+ errors" | grep -oE "^[0-9]+")
  echo
  if [ "${mlkemn:-1}" = "0" ] && [ "${leakyn:-0}" -gt 0 ] 2>/dev/null; then
    echo "DISCRIMINATOR HOLDS on $(uname -m): ML-KEM probe = 0 (clean) vs planted secret branch = $leakyn (leaky)."
  else
    echo "DISCRIMINATOR CHECK on $(uname -m): ML-KEM=${mlkemn:-?}, planted=${leakyn:-?} (expected 0 vs >0)."
    exit 3
  fi
'
