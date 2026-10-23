#!/usr/bin/env bash
# Full installed root-lifecycle cohorts; every failed child propagates to CI.
set -euo pipefail
if [ "$#" -ne 5 ]; then
  echo 'usage: continuity_root_scenarios.sh continuation|winner installed provider native output' >&2
  exit 2
fi
root_lane=$1
root_implementation=$2
root_provider=$3
root_native=$4
root_output=$5
case "$root_lane" in continuation|winner) ;; *) echo 'unknown root lifecycle cohort' >&2; exit 2 ;; esac
mkdir -p "$root_output"

run_case() {
  local root_label=$1
  shift
  sh artifact/python-run.sh research/continuity-openssl-peer/enrollment_session_checks.py \
    --implementation-root "$root_implementation" --provider-root "$root_provider" \
    --native "$root_native" "$@" --output "$root_output/$root_label" \
    > "$root_output/$root_label.stdout" 2> "$root_output/$root_label.stderr"
}

run_pair() {
  local root_flag=$1 root_prefix=$2
  shift 2
  if [ "$#" -ne 2 ]; then echo 'root lifecycle pair requires exactly two cases' >&2; return 2; fi
  local root_pids=() root_case root_pid root_status=0
  for root_case in "$@"; do
    run_case "$root_prefix-$root_case" "$root_flag" "$root_case" &
    root_pids+=("$!")
  done
  for root_pid in "${root_pids[@]}"; do
    if ! wait "$root_pid"; then root_status=1; fi
  done
  return "$root_status"
}

if [ "$root_lane" = continuation ]; then
  for root_mode in peer-root-revocation peer-root-replacement peer-root-continuation replan-plan replan-decision; do
    run_case "root-successor-$root_mode" --root-successor "$root_mode"
  done
  run_case root-successor-process-restart --root-successor-process-restart peer-root-continuation
  run_pair --root-successor-later-cuts later-root-cuts bind retire
  run_pair --root-transition-cuts root-transition-cuts plan decision
  run_pair --root-transition-cancellation root-transition-cancel plan decision
else
  sh artifact/python-run.sh research/continuity-openssl-peer/tests/account_authority_compatibility.py \
    --implementation-root "$root_implementation" --provider-root "$root_provider" \
    --output "$root_output/authority-v1-compatibility.json" \
    > "$root_output/authority-v1-compatibility.stdout" 2> "$root_output/authority-v1-compatibility.stderr"
  for root_mode in bound-fresh bound-reuse unbound-fresh unbound-reuse cross-application; do
    run_case "root-winner-$root_mode" --root-winner-adoption "$root_mode"
  done
  run_pair --root-winner-cuts root-winner-cuts bound-fresh unbound-reuse
  run_pair --root-winner-cancellation root-winner-cancel bound-fresh unbound-reuse
fi
