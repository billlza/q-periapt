# Check the binding proof development with EasyCrypt.
#   make check        # requires `easycrypt` on PATH (+ why3/SMT solvers configured)
#
# Install EasyCrypt via opam (see https://github.com/EasyCrypt/easycrypt):
#   opam pin add easycrypt https://github.com/EasyCrypt/easycrypt.git
#   easycrypt why3config

EC  ?= easycrypt
SRC := BindingViaCR.ec MigrationBindingV2.ec
MIGRATION_SRC := MigrationBindingV2.ec
MIGRATION_LEMMAS := \
	migration_v2_contract_constants_exact \
	migration_body_state_inj \
	migration_policy_context_state_inj \
	state_neq_migration_contextbound_fields_neq \
	mig_bind_k_state_le_cr \
	mig_bind_k_full_state_bad_event_decomposition \
	omitted_state_negative_control

.PHONY: check check-lemma-names
check: check-lemma-names
	@for source in $(SRC); do \
		$(EC) "$$source" || exit $$?; \
	done

check-lemma-names:
	@! grep -Eq '(^|[^[:alnum:]_])(axiom|admit|sorry)([^[:alnum:]_]|$$)' "$(MIGRATION_SRC)" || { \
		echo "forbidden proof assumption in EasyCrypt migration model" >&2; \
		exit 1; \
	}
	@for lemma in $(MIGRATION_LEMMAS); do \
		grep -Eq "^lemma[[:space:]]+$$lemma([[:space:](]|$$)" "$(MIGRATION_SRC)" || { \
			echo "missing EasyCrypt migration lemma: $$lemma" >&2; \
			exit 1; \
		}; \
	done
