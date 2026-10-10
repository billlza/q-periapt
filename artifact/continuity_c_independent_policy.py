"""Exact installed C independent policy, roster and original-account workloads.

Checks complete runtime assertions and scope markers from the selected native
harness. This is not a second protocol or signature implementation.
"""
import re
import rust_sdk_profile as sdk
from continuity_c_enrollment import _require_enrollment_execution

TESTS = {
    'credential_renewal::independent_policy::witnessed::roster::traffic::fanout::c_peer_roster_tls_committed_reply_loss_cancel_and_kill_recover_original_target',
    'credential_renewal::independent_policy::witnessed::roster::traffic::fanout::c_peer_roster_unknown_commit_cancel_and_kill_recover_original_target_without_current_sdk',
    'credential_renewal::independent_policy::c_independent_policy_rejects_changed_requests_without_publishing_or_mutating_intent',
    'credential_renewal::independent_policy::c_independent_policy_request_restarts_exact_stage_and_adopts_original_journal',
    'credential_renewal::independent_policy::c_independent_policy_restores_original_tls_session_after_lost_application_receipt',
    'credential_renewal::independent_policy::public_bindings::public_wrapper_rejects_request_substitution_and_pre_cancelled_stage',
    'credential_renewal::independent_policy::witnessed::c_original_independent_policy_coordinates_applied_and_closed_over_tcp_and_mutual_tls',
    'credential_renewal::independent_policy::witnessed::c_original_policy_lost_commit_or_ack_recovers_without_current_runtime_or_application_tls',
    'credential_renewal::independent_policy::witnessed::roster::c_roster_failed_initial_head_query_retains_unprepared_intent_and_can_abandon_without_witness_terminal',
    'credential_renewal::independent_policy::witnessed::roster::c_roster_processed_commit_and_ack_losses_recover_original_target_without_current_runtime',
    'credential_renewal::independent_policy::witnessed::roster::c_roster_retains_exact_terminal_and_original_owner_under_p0_and_independent_p_tcp_tls',
    'credential_renewal::independent_policy::witnessed::roster::traffic::c_required_policy_roster_preserves_unknown_delivery_then_rekeys_original_tls_session',
    'credential_renewal::independent_policy::witnessed::roster::traffic::fanout::c_required_p_r_keeps_partial_account_batch_and_original_member_results',
    'credential_renewal::independent_policy::witnessed::roster::traffic::fanout::c_required_peer_revocation_reconciles_every_original_account_member_before_retirement',
}
MARKERS = (
    'C_PEER_ROSTER_TLS_INTERRUPTION cases=3 mutual_TLS=true processed_loss=true inflight_cancel=true actual_process_kill=true original_sealed_target=true historical_account_recovery=true distinct_member_outcomes=true no_plaintext_fallback=true',
    'C_PEER_ROSTER_INTERRUPTION cases=4 signed_TCP=true unprocessed_and_processed_loss=true inflight_cancel=true actual_process_kill=true unchanged_error_output=true original_sealed_target=true historical_account_recovery=true distinct_member_outcomes=true',
    'C_INDEPENDENT_POLICY request_from_original=true signed_inputs_reverified=true pending_exact_retry=true first_approvals_retained=true actual_commit=true original_device_transfer=true historical_without_runtime_tls_signer=true',
    'C_INDEPENDENT_POLICY_ERRORS scope=true signature=true tail=true cancellation=true output_untouched=true ownership_checked=true original_intent=true',
    'C_INDEPENDENT_POLICY_TRAFFIC original_tls_session=true original_message=true receiver_effect_once=true unknown_commit_preserved=true acknowledged_after_process_reopen=true original_signer_journal_keys=true native_peer=true',
    'C_INDEPENDENT_WITNESS tcp_and_mutual_tls=true actual_applied_and_closed=true original_target=true complete_proposal=true metadata_without_runtime_signer_TLS=true',
    'C_INDEPENDENT_WITNESS_REPLY_LOSS scenarios=3 exact_pending=true same_target=true original_terminal_before_ACK=true no_runtime_or_application_TLS=true',
    'C_REQUIRED_PEER_REVOCATION cases=2 recipients=2 actual_second_revocation=true TCP_TLS_witness=true partial_confirmed_unknown=true complete_original_reconciliation=true synced_full_reports=true metadata_retired=true',
    'C_REQUIRED_P_R_FANOUT cases=2 recipients=2 TCP_TLS_witness=true original_batch=true partial_confirmed_unknown=true receiver_exit_77=true retained_no_application_exchange=true witness_still_checked=true original_member_retry=true aggregate_bypass_denied=true unchanged_effects=true',
    'C_REQUIRED_P_R_TRAFFIC cases=2 TCP_TLS_witness=true original_session=true original_message=true receiver_exit_77=true effect_not_repeated=true R_ACK_loss=true rekey_1=true bidirectional_after_rekey=true unchanged_bootstrap_and_owner_keys=true',
    'C_ROSTER_LIFECYCLE cases=8 TCP_TLS=true P0_independent_P=true exact_target=true original_owner=true next_R=true next_P_request=true',
    'C_ROSTER_REPLY_LOSS cases=3 actual_processed_reply=true preserved_pending=true no_current_runtime=true original_result=true',
    'C_ROSTER_UNPREPARED actual_query_failure=true no_target=true local_abandonment_distinct=true no_signer_runtime_or_network=true',
    'PUBLIC_POLICY_REFUSALS scope=true signature=true cancellation=true typed_native_errors=true original_pending_unchanged=true',
)

def verify(stdout: bytes, stderr: bytes) -> dict:
    text = stdout.decode()
    _require_enrollment_execution(text, TESTS, "independent C lifecycle workloads were not executed completely")
    # libtest writes result rows to stdout; the harness emits scope evidence
    # with eprintln! on stderr. Require each in its actual captured stream.
    scope = stderr.decode()
    for marker in MARKERS:
        prefix = marker.split(" ", 1)[0]
        sdk.require(re.findall(r"^" + re.escape(prefix) + r" .*?$", scope, re.MULTILINE) == [marker],
                    "independent C lifecycle scope differs: " + prefix)
    return dict(completed=True, tests=sorted(TESTS), language="C",
                scope="installed C client with shared Rust engine; independent local/required policy renewal, atomic local roster refresh, current remote-roster admission, original TLS message/rekey and partial-account recovery through TCP/mTLS witnesses; real second-recipient revocation preserves authenticated consumption versus unknown delivery and requires complete synced host accounting before metadata retirement",
                peer_roster_interruption_carrier="signed-tcp", peer_roster_interruption_cases=4,
                peer_roster_tls_post_commit_interruption_cases=3,
                peer_roster_tls_preprocessing_interruption_qualified=False,
                independent_protocol_implementation=False, Swift_Kotlin_new_paths_qualified=False,
                physical_platform_qualified=False, release_claim_eligible=False)
