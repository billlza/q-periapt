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
prove:
	$(PROVERIF) $(SRC)

check:
	$(PROVERIF) -test $(SRC)
