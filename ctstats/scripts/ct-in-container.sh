#!/usr/bin/env sh
# Run the dataflow constant-time gate (ct_verify under Valgrind/Memcheck) inside a Linux
# container — useful on hosts without a local Valgrind (e.g. macOS). Pick the arch via the
# image platform; on an Apple-Silicon host the default lands on aarch64 natively (fast).
#
#   sh ctstats/scripts/ct-in-container.sh              # native arch of the container VM
#   DOCKER_DEFAULT_PLATFORM=linux/amd64 sh ctstats/scripts/ct-in-container.sh   # x86_64
#
# Requires a working Docker/colima context. Exits non-zero if Memcheck flags any
# secret-dependent branch/index in the suite's composition code (ct_eq/ct_select32/combiner).
set -eu

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)

exec docker run --rm -v "$REPO_ROOT":/work:ro -w /work rust:slim sh -c '
  set -e
  echo "container arch: $(uname -m)"
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq valgrind build-essential >/dev/null 2>&1
  valgrind --version
  export CARGO_TARGET_DIR=/tmp/ctbuild
  cargo build --release -p q-periapt-ctstats --bin ct_verify --features valgrind
  # Negative control: a planted secret-dependent branch MUST be caught (else the gate is
  # vacuous on this target). We assert Valgrind exits non-zero on it.
  cat > /tmp/neg.c <<EOF
#include <valgrind/memcheck.h>
int main(void){unsigned char s=0;VALGRIND_MAKE_MEM_UNDEFINED(&s,1);return (s&1)?1:0;}
EOF
  gcc -O2 /tmp/neg.c -o /tmp/neg
  if valgrind --error-exitcode=1 --leak-check=no /tmp/neg >/dev/null 2>&1; then
    echo "NEGATIVE CONTROL FAILED: Memcheck did not catch a secret-dependent branch"; exit 2
  fi
  echo "negative control OK (Memcheck catches a planted secret branch on this target)"
  # The real gate: composition code must be constant-time.
  valgrind --error-exitcode=1 --leak-check=no --track-origins=yes /tmp/ctbuild/release/ct_verify
  echo "ct_verify: constant-time gate PASSED on $(uname -m)"
'
