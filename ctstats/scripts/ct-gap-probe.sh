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

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
RUNARGS=""
[ -n "${DOCKER_DEFAULT_PLATFORM:-}" ] && RUNARGS="--platform ${DOCKER_DEFAULT_PLATFORM}"

# shellcheck disable=SC2086
exec docker run --rm $RUNARGS -v "$REPO_ROOT":/work:ro -w /work rust:slim sh -c '
  set -e
  echo "=== source->binary CT gap probe; container arch: $(uname -m) ==="
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq valgrind build-essential >/dev/null 2>&1
  valgrind --version
  export CARGO_TARGET_DIR=/tmp/ctbuild
  cargo build --release -p q-periapt-ctstats --bin ct_decaps_gap --features valgrind 2>/dev/null
  BIN=/tmp/ctbuild/release/ct_decaps_gap

  # Negative control: a deliberate secret-dependent branch MUST make Memcheck exit non-zero.
  if valgrind --error-exitcode=1 --leak-check=no -q "$BIN" control >/dev/null 2>&1; then
    echo "NEGATIVE CONTROL FAILED on $(uname -m): planted secret branch NOT caught — probe vacuous"
    exit 2
  fi
  echo "negative control OK: Memcheck catches a planted secret branch on $(uname -m)"
  echo

  run() {
    valgrind --leak-check=no --track-origins=yes "$BIN" "$1" >/tmp/out."$1" 2>&1 || true
    summary=$(grep "ERROR SUMMARY" /tmp/out."$1" | tail -1 | sed "s/^==[0-9]*== //")
    printf "  %-8s %s\n" "$1:" "$summary"
  }
  echo "Memcheck error summaries (marking the named field(s) secret, real libcrux decapsulate):"
  run wholedk   # all 2400 dk bytes  -> baseline (~2848 errors / 30 contexts, on embedded ek)
  run ek        # ek[1152..2336]     -> attribution (the ~30 q-branches are on the PUBLIC key)
  run probe     # ŝ[0..1152]+z[2368..2400] -> THE GAP QUESTION (0 = no source->binary gap)
  echo
  echo "interpretation: probe = 0 errors  => libcrux ML-KEM decaps secret-independence survives"
  echo "                compilation on $(uname -m) (no source->binary CT gap on the ŝ/z path)."

  # DISCRIMINATOR: the SAME probe on a KNOWN-LEAKY primitive (HQC, PQClean C). If HQC were
  # also 0 the probe would be vacuous; HQC > 0 proves the probe actually distinguishes clean
  # from leaky. The leak is PQClean vect_set_random_fixed_weight (secret-dependent control flow).
  echo
  echo "=== discriminator: same probe on HQC (PQClean C), marking the genuine secret prefix ==="
  cargo build --release -p q-periapt-ctstats --bin ct_hqc_gap --features valgrind,hqc 2>/dev/null
  HBIN=/tmp/ctbuild/release/ct_hqc_gap
  valgrind --leak-check=no --track-origins=yes "$HBIN" prefix >/tmp/out.hqc 2>&1 || true
  hqcsum=$(grep "ERROR SUMMARY" /tmp/out.hqc | tail -1 | sed "s/^==[0-9]*== //")
  printf "  %-8s %s\n" "hqc:" "$hqcsum"
  mlkemn=$(grep "ERROR SUMMARY" /tmp/out.probe | tail -1 | grep -oE "[0-9]+ errors" | grep -oE "^[0-9]+")
  hqcn=$(grep "ERROR SUMMARY" /tmp/out.hqc   | tail -1 | grep -oE "[0-9]+ errors" | grep -oE "^[0-9]+")
  echo
  if [ "${mlkemn:-1}" = "0" ] && [ "${hqcn:-0}" -gt 0 ] 2>/dev/null; then
    echo "DISCRIMINATOR HOLDS on $(uname -m): ML-KEM probe = 0 (clean) vs HQC prefix = $hqcn (leaky)."
  else
    echo "DISCRIMINATOR CHECK on $(uname -m): ML-KEM=${mlkemn:-?}, HQC=${hqcn:-?} (expected 0 vs >0)."
  fi
'
