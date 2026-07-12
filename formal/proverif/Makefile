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
# `prove` is a real gate: ProVerif may exit 0 even when a query is not proved, so match
# every expected RESULT independently and reject missing, duplicate, or additional results.
# The one expected "is false" is the executability query (`RESULT not event(...) is false`
# means the ClientFinish event IS reachable).
prove:
	@set -eu; \
	OUT=`$(PROVERIF) $(SRC)`; \
	printf '%s\n' "$$OUT"; \
	require_result() { \
		LABEL="$$1"; NEEDLE="$$2"; SUFFIX="$$3"; \
		MATCHES=`printf '%s\n' "$$OUT" | awk -v needle="$$NEEDLE" -v suffix="$$SUFFIX" \
			'index($$0, "RESULT ") == 1 && index($$0, needle) > 0 && \
			 substr($$0, length($$0) - length(suffix) + 1) == suffix { n++ } \
			 END { print n + 0 }'`; \
		[ "$$MATCHES" -eq 1 ] || { \
			echo "FAIL: expected exactly one RESULT for $$LABEL, found $$MATCHES"; exit 1; \
		}; \
		echo "OK: $$LABEL"; \
	}; \
	RESULTS=`printf '%s\n' "$$OUT" | awk '/^RESULT / { n++ } END { print n + 0 }'`; \
	[ "$$RESULTS" -eq 6 ] || { echo "FAIL: expected exactly 6 RESULT lines, found $$RESULTS"; exit 1; }; \
	require_result executability 'not event(ClientFinish(' 'is false.'; \
	require_result injective-auth 'inj-event(ClientFinish(' 'is true.'; \
	require_result context-agreement ' ==> event(ServerDone(' 'is true.'; \
	require_result hybrid-secrecy '==> (event(RevealPQ(' 'is true.'; \
	require_result pq-break-survived '==> event(RevealTrad(' 'is true.'; \
	require_result traditional-break-survived '==> event(RevealPQ(' 'is true.'; \
	echo "OK: all 6 expected ProVerif query results matched exactly"

check:
	$(PROVERIF) -test $(SRC)
