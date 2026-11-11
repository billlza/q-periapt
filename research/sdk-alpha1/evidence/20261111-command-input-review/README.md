# Command-input review for the current SDK candidate

The attached bounded source reviews follow origins 5–23 of the retained Python command-line-injection result into SDK commit 4870db5eff0a611973a302f29e94c0992df66cfe, tree 7d4ca678175170b6c867240727f3908bc2d7c1f1. The prior packet covers origins 1–4. The SARIF retains four complete codeFlows for 23 listed origins; the additional origins are traced manually, with reading coverage stated per entry.

The inspected calls use explicit local tool selection, controlled build outputs or test fixtures. This source review identified no new lower-trust network or protocol input crossing the inspected execution boundaries. It records the launcher version-before-hash ordering and the current workflow's preceding fixed-bundle verification. Tool selection, shell=False and prior authentication are treated separately.

This branch adds review evidence only. It executes no reported path and changes no product source, rule or alert disposition. Child-harness and optional-consumer coverage limits remain attached to the observations. The four separate matched-auditor path findings and ten executed controls remain in the candidate's 20261111-matched-auditor-findings packet.
