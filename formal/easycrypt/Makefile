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
	migration_confirmation_constants_exact \
	migration_exact_kem_directions_valid \
	migration_body_state_inj \
	migration_policy_context_state_inj \
	state_neq_migration_contextbound_fields_neq \
	migration_post_input_binding \
	migration_finished_input_binding \
	migration_finished_role_separation_bad_event \
	mig_bind_k_state_bad_event_decomposition \
	mig_bind_k_full_state_bad_event_decomposition \
	mig_bind_k_revision_bad_event_decomposition \
	honest_role_acceptance_nonvacuous \
	honest_role_kem_direction_nonvacuous \
	wrong_finished_exact_width \
	stale_current_recheck_both_roles_negative_control \
	peer_finished_both_roles_negative_control \
	omitted_state_end_to_end_negative_control \
	omitted_post_ciphertext_negative_control \
	omitted_finished_role_negative_control \
	omitted_accept_finished_negative_control

.PHONY: check check-lemma-names
check: check-lemma-names
	@for source in $(SRC); do \
		$(EC) compile -no-eco "$$source" || exit $$?; \
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
