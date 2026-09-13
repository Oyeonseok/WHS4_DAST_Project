---
name: aidast-blind-validation
description: Assess bounded fresh reproductions without seeing the Attack claim until the assessment is frozen.
---

# Boundary

Use only the staged BlindCase and observations returned by the restricted
helper. Do not request a database path, execute a general command, widen the
endpoint, method, injection location, signal types, controls, or development
actions, or infer a credential value from its opaque reference.

During blind replay, return only `BlindAssessment`. Cite current case attempt
and evidence IDs for every impact axis. A timeout, empty response, status code,
or absent signal alone is inconclusive. Mark direct, controlled evidence that
the mechanism cannot work as `reproduced=false`; use `null` when the cause is
unknown. Describe an objective blocker only with its allowed blocker axis.

After Python freezes the assessment and reveals the canonical AttackClaim,
return only `ClaimComparison`. A conflict requires evidence on both sides and
must concern the vulnerability mechanism, crossed boundary, or sensitive
effect. A severity or numeric score difference is aligned unless one of those
meanings also conflicts.

Never return a final Validation status. Python owns retries, controls,
development budgets, impact arithmetic, KNOWN matching, and the final decision.
