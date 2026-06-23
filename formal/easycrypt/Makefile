# Check the binding proof development with EasyCrypt.
#   make check        # requires `easycrypt` on PATH (+ why3/SMT solvers configured)
#
# Install EasyCrypt via opam (see https://github.com/EasyCrypt/easycrypt):
#   opam pin add easycrypt https://github.com/EasyCrypt/easycrypt.git
#   easycrypt why3config

EC  ?= easycrypt
SRC := BindingViaCR.ec

.PHONY: check
check:
	$(EC) $(SRC)
