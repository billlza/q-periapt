# syntax=docker/dockerfile:1
# Hermetic EasyCrypt environment for re-checking the Q-Periapt binding proofs as a CI HARD GATE.
# Pins the EXACT EasyCrypt dev commit the proofs were written against (r2026.06, 50ae51d) plus Why3
# and the Z3 / Alt-Ergo SMT solvers, so `make check` + the negative-control necessity script run
# deterministically in CI — replacing the previous best-effort, continue-on-error opam install.
#
# Build:  docker build -f formal/Dockerfile -t q-periapt-ec .
# Check:  docker run --rm -v "$PWD/formal/easycrypt:/work" q-periapt-ec \
#             opam exec -- sh -c 'rm -f *.eco && easycrypt BindingViaCR.ec && sh negative-controls.sh'
FROM ocaml/opam:debian-12-ocaml-5.3

# Base tools + the Z3 solver. The apt lists are intentionally KEPT so opam can resolve and install
# EasyCrypt's own system depexts (zlib, pcre2, gmp, ...) itself, rather than us guessing them.
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
      z3 git make ca-certificates sudo
USER opam

# The exact EasyCrypt the proofs check under (matches the development host: r2026.06-6-g50ae51d).
ARG EC_COMMIT=50ae51d
RUN opam update && \
    opam pin add -y -n easycrypt "git+https://github.com/EasyCrypt/easycrypt.git#${EC_COMMIT}" && \
    opam install -y --confirm-level=unsafe-yes easycrypt alt-ergo && \
    opam clean -y

# Let EasyCrypt/Why3 discover the SMT solvers (z3 from apt, alt-ergo from opam).
RUN opam exec -- why3 config detect

WORKDIR /work
