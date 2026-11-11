# Exact Android failure-upload contract

The published integration check ran 3,787 Python checks and found one stale exact workflow-step expectation after the new Android failure diagnostics were added. The corresponding canonical expectation had the same omission. This repair retains the exact allowlist and its forbidden broad-pattern checks, adds the six new integration paths (nine canonical paths), and removes three duplicate integration upload entries. The receipt records the two integration checks or one canonical check actually executed on the corresponding source.
