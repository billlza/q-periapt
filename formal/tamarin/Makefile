# Machine-check the handshake protocol model with Tamarin.
#   make prove        # prove all lemmas (requires `tamarin-prover` + `maude` on PATH)
#   make check        # parse + wellformedness only (fast)
#
# Install Tamarin (https://tamarin-prover.com/manual/master/book/002_installation.html):
#   brew install tamarin-prover        # macOS (pulls in maude)

TAMARIN ?= tamarin-prover
SRC     := handshake.spthy

.PHONY: prove check
prove:
	$(TAMARIN) --prove $(SRC)

check:
	$(TAMARIN) $(SRC)
