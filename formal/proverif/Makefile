# Machine-check the handshake protocol model with ProVerif.
#   make prove        # prove all queries (requires `proverif` on PATH)
#   make check        # syntax/typing check only (fast; -test gives extra detail)
#
# Install ProVerif via OPAM (https://bblanche.gitlabpages.inria.fr/proverif/):
#   opam install proverif             # CLI verifier (pulls lablgtk for the optional GUI)
# On macOS the lablgtk dependency needs gtk+/expat first:
#   brew install gtk+ expat && opam install --assume-depexts proverif

PROVERIF ?= proverif
SRC      := handshake.pv

.PHONY: prove check
# `prove` is a real gate: it fails unless the four security queries (injective server
# authentication, hybrid secrecy, and the two single-break robustness corners) are each
# proved. ProVerif exits 0 regardless, so we assert on its RESULT lines. The one expected
# "is false" is the executability query (`RESULT not event(...) is false` means the
# ClientFinish event IS reachable).
prove:
	@OUT=`$(PROVERIF) $(SRC)`; \
	echo "$$OUT"; \
	N=`echo "$$OUT" | grep -c 'RESULT.* is true'`; \
	[ "$$N" -ge 4 ] || { echo "FAIL: only $$N/4 security queries proved true"; exit 1; }; \
	echo "OK: $$N security queries proved true (+ executability reachable)"

check:
	$(PROVERIF) -test $(SRC)
