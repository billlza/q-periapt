# Machine-check the handshake protocol model with Tamarin.
#   make prove        # prove all lemmas (requires `tamarin-prover` + `maude` on PATH)
#   make check        # parse + wellformedness only (fast)
#
# Install Tamarin (https://tamarin-prover.com/manual/master/book/002_installation.html):
#   brew install tamarin-prover        # macOS (pulls in maude)

TAMARIN ?= tamarin-prover
DERIVCHECK_TIMEOUT ?= 60

HANDSHAKE_SRC := handshake.spthy
MIGRATION_STATE_SRC := migration_v2.spthy
MIGRATION_AGREEMENT_SRC := migration_v2_agreement.spthy
MIGRATION_LIVENESS_SRC := migration_v2_liveness.spthy
MIGRATION_ROLLBACK_SRC := migration_v2_rollback.spthy
MIGRATION_NO_WITNESS_SRC := migration_v2_no_witness.spthy
MIGRATION_NEGATIVE_SRC := migration_v2_negative_controls.spthy
SRC := $(HANDSHAKE_SRC) $(MIGRATION_STATE_SRC) $(MIGRATION_AGREEMENT_SRC) \
	$(MIGRATION_LIVENESS_SRC) $(MIGRATION_ROLLBACK_SRC) \
	$(MIGRATION_NO_WITNESS_SRC) $(MIGRATION_NEGATIVE_SRC)

HANDSHAKE_LEMMAS := executable server_authentication \
	authenticated_context_agreement hybrid_secrecy \
	hybrid_robustness_authenticated
MIGRATION_STATE_LEMMAS := state_reservation_executable \
	restored_old_store_executable transition_authenticity reset_authorization \
	mig_floor mig_floor_transition
MIGRATION_AGREEMENT_LEMMAS := migration_executable mig_agree_initiator \
	mig_agree_responder mig_agree_both_accept
MIGRATION_LIVENESS_LEMMAS := successor_state_executable
MIGRATION_ROLLBACK_LEMMAS := current_reservation_accepts \
	concurrent_reservation_becomes_stale \
	restored_old_store_after_retire_executable mig_rollback \
	mig_no_unauthorized_fork
MIGRATION_NO_WITNESS_LEMMAS := rollback_without_witness_executable
MIGRATION_NEGATIVE_LEMMAS := untyped_finished_reflection_executable \
	below_floor_without_closed_relation_executable

.PHONY: prove check check-lemma-names
prove: check-lemma-names
	@set -eu; \
	for spec in \
		"$(HANDSHAKE_SRC)|$(HANDSHAKE_LEMMAS)" \
		"$(MIGRATION_AGREEMENT_SRC)|$(MIGRATION_AGREEMENT_LEMMAS)" \
		"$(MIGRATION_LIVENESS_SRC)|$(MIGRATION_LIVENESS_LEMMAS)" \
		"$(MIGRATION_ROLLBACK_SRC)|$(MIGRATION_ROLLBACK_LEMMAS)" \
		"$(MIGRATION_NO_WITNESS_SRC)|$(MIGRATION_NO_WITNESS_LEMMAS)" \
		"$(MIGRATION_NEGATIVE_SRC)|$(MIGRATION_NEGATIVE_LEMMAS)"; do \
		file=$${spec%%|*}; lemmas=$${spec#*|}; \
		output="$$( $(TAMARIN) --quit-on-warning \
			--derivcheck-timeout=$(DERIVCHECK_TIMEOUT) --prove "$$file" 2>&1 )" || { \
			printf '%s\n' "$$output"; exit 1; \
		}; \
		printf '%s\n' "$$output" | sed -n '/summary of summaries:/,$$p'; \
		for lemma in $$lemmas; do \
			printf '%s\n' "$$output" | grep -Eq "^  $$lemma .*: verified" || { \
				echo "Tamarin did not verify $$lemma in $$file" >&2; exit 1; \
			}; \
		done; \
	done
	@set -eu; \
	for lemma in $(MIGRATION_STATE_LEMMAS); do \
		output="$$( $(TAMARIN) --quit-on-warning \
			--derivcheck-timeout=$(DERIVCHECK_TIMEOUT) \
			--prove=$$lemma "$(MIGRATION_STATE_SRC)" 2>&1 )" || { \
			printf '%s\n' "$$output"; exit 1; \
		}; \
		printf '%s\n' "$$output" | sed -n '/summary of summaries:/,$$p'; \
		printf '%s\n' "$$output" | grep -Eq "^  $$lemma .*: verified" || { \
			echo "Tamarin did not verify $$lemma in $(MIGRATION_STATE_SRC)" >&2; \
			exit 1; \
		}; \
	done

check:
	@for source in $(SRC); do \
		$(TAMARIN) --quit-on-warning --parse-only "$$source" >/dev/null || exit $$?; \
	done

check-lemma-names:
	@set -eu; \
	for spec in \
		"$(HANDSHAKE_SRC)|$(HANDSHAKE_LEMMAS)" \
		"$(MIGRATION_STATE_SRC)|$(MIGRATION_STATE_LEMMAS)" \
		"$(MIGRATION_AGREEMENT_SRC)|$(MIGRATION_AGREEMENT_LEMMAS)" \
		"$(MIGRATION_LIVENESS_SRC)|$(MIGRATION_LIVENESS_LEMMAS)" \
		"$(MIGRATION_ROLLBACK_SRC)|$(MIGRATION_ROLLBACK_LEMMAS)" \
		"$(MIGRATION_NO_WITNESS_SRC)|$(MIGRATION_NO_WITNESS_LEMMAS)" \
		"$(MIGRATION_NEGATIVE_SRC)|$(MIGRATION_NEGATIVE_LEMMAS)"; do \
		file=$${spec%%|*}; lemmas=$${spec#*|}; \
		for lemma in $$lemmas; do \
			grep -Eq "^lemma[[:space:]]+$$lemma([[:space:]]+\\[[^]]+\\])?:" "$$file" || { \
				echo "missing Tamarin lemma $$lemma in $$file" >&2; exit 1; \
			}; \
		done; \
	done
