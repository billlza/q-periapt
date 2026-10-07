#!/usr/bin/env sh
# Binary dataflow probe over every shipped ML-KEM expanded-DK wrapper. For each FIPS 203
# parameter set, mark only the genuine secret (s-hat + z), exercise valid and invalid
# ciphertexts, require a planted-secret control to be detected, and require the real probe to
# report exact 0 errors / 0 contexts.
#
#   sh ctstats/scripts/ct-gap-probe.sh
#   DOCKER_DEFAULT_PLATFORM=linux/amd64 sh ctstats/scripts/ct-gap-probe.sh
#
# This is target/build-specific empirical evidence, not a source-level constant-time proof.
set -eu

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
if [ -n "${DOCKER_DEFAULT_PLATFORM:-}" ]; then
  set -- --platform "$DOCKER_DEFAULT_PLATFORM"
else
  set --
fi

exec docker run --rm "$@" -v "$REPO_ROOT":/work:ro -w /work rust:slim sh -c '
  set -eu
  echo "=== shipped q-periapt-backends ML-KEM dataflow probes; container arch: $(uname -m) ==="
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq valgrind build-essential >/dev/null 2>&1
  valgrind --version
  export CARGO_TARGET_DIR=/tmp/ctbuild
  export CARGO_TERM_COLOR=never
  export RUSTFLAGS=-Dwarnings
  cargo build --locked --release -p q-periapt-ctstats --bin ct_decaps_gap --features valgrind
  BIN=/tmp/ctbuild/release/ct_decaps_gap

  summary() {
    grep "ERROR SUMMARY" "$1" | tail -1 | sed "s/^==[0-9]*== //"
  }

  for parameter in 512 768 1024; do
    echo
    echo "=== ML-KEM-$parameter ==="

    # Only the dedicated Valgrind sentinel plus a positive summary proves the planted control.
    set +e
    valgrind --error-exitcode=99 --leak-check=no --track-origins=yes \
      "$BIN" "$parameter" control >"/tmp/out.$parameter.control" 2>&1
    control_rc=$?
    set -e
    if [ "$control_rc" -ne 99 ] || \
       ! grep -Eq "ERROR SUMMARY: [1-9][0-9]* errors" "/tmp/out.$parameter.control"; then
      cat "/tmp/out.$parameter.control"
      echo "CONTROL FAILED for ML-KEM-$parameter on $(uname -m): expected rc=99 and a positive error summary, got rc=$control_rc"
      exit 2
    fi
    printf "  %-10s %s\n" "control:" "$(summary "/tmp/out.$parameter.control")"

    # Public-field and whole-key over-marking remain optional diagnostics. They carry no fixed
    # expectation and are intentionally not part of the secret-only release verdict.
    for mode in ek wholedk; do
      valgrind --leak-check=no --track-origins=yes \
        "$BIN" "$parameter" "$mode" >"/tmp/out.$parameter.$mode" 2>&1
      printf "  %-10s %s\n" "$mode:" "$(summary "/tmp/out.$parameter.$mode")"
    done

    # Load-bearing gate: exact zero errors from zero contexts for genuine s-hat+z on both paths.
    set +e
    valgrind --error-exitcode=97 --leak-check=no --track-origins=yes \
      "$BIN" "$parameter" probe >"/tmp/out.$parameter.probe" 2>&1
    probe_rc=$?
    set -e
    if [ "$probe_rc" -ne 0 ] || \
       ! grep -Fq "ERROR SUMMARY: 0 errors from 0 contexts" "/tmp/out.$parameter.probe"; then
      cat "/tmp/out.$parameter.probe"
      echo "PROBE FAILED for ML-KEM-$parameter on $(uname -m): expected rc=0 and exact 0 errors / 0 contexts, got rc=$probe_rc"
      exit 3
    fi
    printf "  %-10s %s\n" "probe:" "$(summary "/tmp/out.$parameter.probe")"
  done

  # Independent dependency-free discriminator: protects against a vacuous/no-op harness even if
  # a future edit accidentally weakens every provider-specific planted control in the same way.
  echo
  echo "=== independent planted-secret discriminator ==="
  cargo build --locked --release -p q-periapt-ctstats --bin ct_leaky_control --features valgrind
  LEAKY_BIN=/tmp/ctbuild/release/ct_leaky_control
  set +e
  valgrind --error-exitcode=99 --leak-check=no --track-origins=yes \
    "$LEAKY_BIN" planted >/tmp/out.leaky-control 2>&1
  leaky_rc=$?
  set -e
  if [ "$leaky_rc" -ne 99 ] || \
     ! grep -Eq "ERROR SUMMARY: [1-9][0-9]* errors" /tmp/out.leaky-control; then
    cat /tmp/out.leaky-control
    echo "LEAKY CONTROL FAILED on $(uname -m): expected rc=99 and a positive error summary, got rc=$leaky_rc"
    exit 4
  fi
  printf "  %-16s %s\n" "leaky-control:" "$(summary /tmp/out.leaky-control)"
  echo
  echo "PASS on $(uname -m): ML-KEM-512/768/1024 genuine-secret probes are all 0/0 and every planted control is positive."
'
