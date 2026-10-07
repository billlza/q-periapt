# Non-normative LifecycleContextV1 projection and omission diagnostics.
EC ?= easycrypt
SRC := LifecycleContextV1.ec PrekeySelectionV1.ec

.PHONY: check
check:
	@for source in $(SRC); do \
		$(EC) compile -no-eco "$$source" || exit 1; \
	done
