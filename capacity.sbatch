#!/bin/bash
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin
export GITHUB_SHA=${1:?expected source commit}
[[ $GITHUB_SHA =~ ^[0-9a-f]{40}$ ]]
test "${SLURM_CPUS_PER_TASK:?}" = 4
test "${SLURM_MEM_PER_NODE:?}" = 65536
# --chdir selects the execution directory; SLURM_SUBMIT_DIR is the client cwd.
staging=$(pwd -P)
test -d "$staging/source/artifact"
result_directory="$staging/results/$SLURM_JOB_ID"
mkdir -p "$result_directory"
node_workspace=$(mktemp -d "/tmp/qperiapt-codeql.$SLURM_JOB_ID.XXXXXXXX")
preserve() {
  original_status=$?
  trap - EXIT
  set +e
  printf '%s\n' "$original_status" > "$result_directory/exit-status.txt"
  printf '%s\n' "$node_workspace" > "$result_directory/node-workspace.txt"
  df -Pk "$node_workspace" > "$result_directory/disk-after.txt"
  members=()
  for member in evidence results; do
    if [[ -d "$node_workspace/run/$member" ]]; then members+=("$member"); fi
  done
  if [[ ${#members[@]} -gt 0 ]]; then
    tar --zstd -cf "$result_directory/evidence.tar.zst" -C "$node_workspace/run" "${members[@]}"
    archive_status=$?
    if [[ $archive_status -ne 0 ]]; then exit "$archive_status"; fi
    sha256sum "$result_directory/evidence.tar.zst" > "$result_directory/evidence.sha256"
    digest_status=$?
    if [[ $digest_status -ne 0 ]]; then exit "$digest_status"; fi
  fi
  # Remove only this job's private scratch after preserving its results.
  rm -rf -- "$node_workspace"
  cleanup_status=$?
  if [[ $cleanup_status -ne 0 ]]; then exit "$cleanup_status"; fi
  exit "$original_status"
}
trap preserve EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
scontrol show job -o "$SLURM_JOB_ID" > "$result_directory/slurm-job.txt"
df -Pk "$node_workspace" > "$result_directory/disk-before.txt"
cp -R "$staging/source" "$node_workspace/source"
cd "$node_workspace/source"
sha256sum --check --strict SOURCE.sha256 > "$result_directory/source-verification.txt"
export QPERIAPT_PYTHON=/usr/bin/python3
sh artifact/python-run.sh -m unittest -v \
  test_codeql_summary_control test_codeql_summary_archive_input test_codeql_process_resources \
  test_codeql_summary_plan test_codeql_progress test_codeql_summary_projection \
  test_codeql_summary_capacity 2>&1 | tee "$result_directory/preflight-tests.log"
printf '%s  %s\n' \
  acf2050189aeede5b9aa566f8fb382b02ac1ace72f534778f68b06fce5371cea "$staging/codeql-bundle-rust-linux64.tar.zst" \
  cb0bd89478b9a8d0f635a9ffa2156a06e3fbbf81b0054b8a1a474c045711d43d "$staging/retained-codeql-database.zip" \
  | sha256sum --check --strict > "$result_directory/input-verification.txt"
mkdir -m 700 "$node_workspace/tool"
tar --zstd --extract --file "$staging/codeql-bundle-rust-linux64.tar.zst" --directory "$node_workspace/tool"
export RUNNER_TEMP="$node_workspace"
timeout --signal=TERM --kill-after=30s 330m \
  sh artifact/python-run.sh artifact/codeql_summary_control.py run \
    --codeql "$node_workspace/tool/codeql/codeql" \
    --tool-archive "$staging/codeql-bundle-rust-linux64.tar.zst" \
    --retained-archive "$staging/retained-codeql-database.zip" \
    --profile memory-56000 --summary-plan-mode projection \
    --output "$node_workspace/run"
