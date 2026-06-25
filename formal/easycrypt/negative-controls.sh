#!/usr/bin/env sh
# Deleted-hypothesis NEGATIVE CONTROLS for the separation map (Theorem 1 / appendix app:sepproof).
#
# A passing machine proof certifies only that the conclusion follows from the stated hypotheses; it
# does NOT certify the hypotheses are necessary. For each load-bearing hypothesis we delete it from
# the proof's `smt()` hint and CONFIRM the proof now FAILS. That is what upgrades the separation map
# from a list of sufficient conditions to a NECESSITY claim ("ContextBound MUST absorb pk_pq and
# context"). Run:  sh formal/easycrypt/negative-controls.sh
set -u
EC="${EASYCRYPT:-$(command -v easycrypt 2>/dev/null || echo "$HOME/.opam/default/bin/easycrypt")}"
SRC="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/BindingViaCR.ec"
pass=0; fail=0

ctl() { # label  perl-substitution-deleting-the-hypothesis
  tmp=$(mktemp /tmp/nc.XXXXXX); mv "$tmp" "$tmp.ec"; tmp="$tmp.ec"
  cp "$SRC" "$tmp"; perl -0pi -e "$2" "$tmp"
  if "$EC" compile "$tmp" >/dev/null 2>&1; then
    echo "  FAIL  [$1] proof STILL checks with the hypothesis deleted => NOT load-bearing"; fail=$((fail+1))
  else
    echo "  ok    [$1] proof fails without it => load-bearing (necessity confirmed)"; pass=$((pass+1))
  fi
  rm -f "$tmp"
}

echo "baseline: the unmodified development must check..."
if "$EC" compile "$SRC" >/dev/null 2>&1; then echo "  ok    baseline checks (no proof holes)"; else echo "  FAIL baseline does not check"; exit 2; fi
echo "deleted-hypothesis negative controls (each MUST fail to check):"
ctl "K-PK break needs two distinct keys (ek_neq)"      's/\Qsmt(ek_neq lean_eq lpk_mk)\E/smt(lean_eq lpk_mk)/'
ctl "K-CTX break needs two distinct contexts (lctx_neq)" 's/\Qsmt(lctx_neq omitctx_eq lctxo_mkc)\E/smt(omitctx_eq lctxo_mkc)/'
ctl "K-CT safety needs J injective (jrej_inj)"         's/\Qsmt(jrej_inj)\E/smt()/'
ctl "seed-dk K-PK safety needs jrej_inj/zof_inj"       's/\Qsmt(jrej_inj zof_inj)\E/smt()/'
ctl "every reduction needs encode_inj (full K-CT)"     's/\Qsmt(encode_inj lct_neq_full_neq)\E/smt(lct_neq_full_neq)/'
ctl "joint X-Wing K-PK break needs ek_neq"             's/\Qsmt(ek_neq xwing_eq_pk lpk_mk)\E/smt(xwing_eq_pk lpk_mk)/'
ctl "joint X-Wing K-CT safety needs jrej_inj"          's/\Qsmt(encode_inj lct_neq_xwing_neq)\E/smt(lct_neq_xwing_neq)/'
echo "summary: $pass load-bearing (ok), $fail not-load-bearing (FAIL)"
[ "$fail" -eq 0 ] && echo "ALL NEGATIVE CONTROLS PASS: every deleted hypothesis breaks its proof." || exit 1
