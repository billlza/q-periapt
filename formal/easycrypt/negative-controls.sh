#!/usr/bin/env sh
# Proof-dependency regression controls for the separation-map development.
#
# Each control removes a named fact from one `smt()` hint and checks that the CURRENT proof script
# no longer compiles. This detects accidental changes to the proof's documented dependencies; it
# does NOT establish that a fact is logically necessary, because tactic failure is not a semantic
# counterexample. Logical necessity must be supported separately by a checked counterexample (for
# example `kctx_without_nonbottom_broken` in BindingViaCR.ec).
#
# The historical filename is retained because CI invokes it directly. Run:
#   sh formal/easycrypt/negative-controls.sh
set -u
EC="${EASYCRYPT:-$(command -v easycrypt 2>/dev/null || echo "$HOME/.opam/default/bin/easycrypt")}"
SRC="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/BindingViaCR.ec"
pass=0; fail=0

ctl() { # label  perl-substitution-removing-the-named-SMT-hint
  tmp=$(mktemp /tmp/nc.XXXXXX); mv "$tmp" "$tmp.ec"; tmp="$tmp.ec"
  cp "$SRC" "$tmp"; perl -0pi -e "$2" "$tmp"
  if "$EC" compile "$tmp" >/dev/null 2>&1; then
    echo "  FAIL  [$1] edited proof still checks; documented script dependency changed"; fail=$((fail+1))
  else
    echo "  ok    [$1] edited proof fails as expected; script dependency retained"; pass=$((pass+1))
  fi
  rm -f "$tmp"
}

echo "baseline: the unmodified development must check..."
if "$EC" compile "$SRC" >/dev/null 2>&1; then echo "  ok    baseline checks (no proof holes)"; else echo "  FAIL baseline does not check"; exit 2; fi
echo "proof-dependency regression controls (each edited proof MUST fail to check):"
ctl "lean K-PK counterexample / ek_neq hint"            's/\Qsmt(ek_neq lean_eq lpk_mk)\E/smt(lean_eq lpk_mk)/'
ctl "omit-context K-CTX counterexample / lctx_neq hint" 's/\Qsmt(lctx_neq omitctx_eq lctxo_mkc)\E/smt(omitctx_eq lctxo_mkc)/'
ctl "omit-ct K-CT reduction / jrej_inj hint"            's/\Qsmt(jrej_inj)\E/smt()/'
ctl "seed-dk K-PK reduction / jrej_inj,zof_inj hints"   's/\Qsmt(jrej_inj zof_inj)\E/smt()/'
ctl "full K-CT reduction / encode_inj hint"             's/\Qsmt(encode_inj lct_neq_full_neq)\E/smt(lct_neq_full_neq)/'
ctl "joint X-Wing K-PK counterexample / ek_neq hint"    's/\Qsmt(ek_neq xwing_eq_pk lpk_mk)\E/smt(xwing_eq_pk lpk_mk)/'
ctl "joint X-Wing K-CT reduction / jrej_inj hint"       's/\Qsmt(encode_inj lct_neq_xwing_neq)\E/smt(lct_neq_xwing_neq)/'
echo "summary: $pass expected script dependencies retained, $fail changed dependencies"
[ "$fail" -eq 0 ] && echo "ALL PROOF-DEPENDENCY REGRESSION CONTROLS PASS." || exit 1
