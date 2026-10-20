# Checkpointed stable maintenance

`stable-maintenance.yml` selects branches and holds the existing shared Azure
concurrency queue for each entire branch pipeline. It calls
`stable-maintenance-branch.yml`, which sequences fresh runner jobs using
`stable-maintenance-stage.yml`:

1. Baseline import refresh and dependency updates.
2. Dependency vetting/rollback and the separately validated Dependabot pin import.
3. Four ordered backport batches, each with a two-hour processing budget.
4. Version preparation, fresh private final gates, and PR publication.

This avoids adding dependency review and every backport to one hosted runner's
six-hour deadline. Retry attempt counts, service cooldowns and per-operation wait
budgets are unchanged. A batch does not wait past its own remaining budget or
start an unbounded contained command: it rolls back the in-flight candidate and
hands the preceding completed tree to the next job. An interrupted attempt is
marked pending for retry/manual review on a later run, so subsequent batches
continue later independent candidates instead of repeatedly timing out on it.
Candidates not yet started remain in the next batch's inventory. Ordinary failed builds still
revert that attempt and continue independent candidates. Each new batch performs
its own baseline build; every new backport still gets its isolated locked build
before formatting/acceptance. There is no shared build cache.

## Image provisioning

The pinned image retains APT's three per-file acquisition retries. If an index
refresh still fails solely with explicit transient HTTP 408/429/500/502/503/504
fetch errors, provisioning retries that refresh up to three more times after
60, 120 and 240 seconds. Integrity, signature, configuration and local execution
errors fail immediately; package installation is not replayed. The reviewed
snapshot, signature/hash checks, 35-minute combined native provisioning deadline
and 45-minute image-step deadline remain unchanged. A sustained remote outage
still fails; rerun the failed job after the service recovers to reuse its saved
predecessor checkpoint.

## Handoff and trust boundary

At a successful stage boundary, a short-lived scoped App token pushes a
run/attempt/stage-specific transport branch under
`automation/stable-maintenance/checkpoints/`. These branches are **not releases**
and do not open PRs. Its tip is a transport commit with an empty tree and exactly
one parent: the clean completed source commit. This keeps unvalidated source and
its workflow definitions off the pushed tip, rather than letting an App-token
push execute staged workflows outside the sandbox. Inspect the tip's parent to
view the staged source. Resume verifies this structure and checks out the exact
source SHA; the transport commit never enters a release PR. Main and stable refs
are never updated by a checkpoint. The dependency-stage parent can still contain
tentative, not-yet-vetted updates.

Only allowlisted structured progress is uploaded as `checkpoint.json`; raw
captures, model responses, credentials and final-gate claims are not transferred.
The next job downloads the named artifact from the same workflow run, checks its
SHA-256 against its predecessor's job output, and verifies the run, stage,
immutable trusted main/tooling SHA, expected source commit, stable base and Git
ancestry. A changed staging ref or advanced stable branch stops the pipeline.
All scripts, reusable workflows and the pinned image definition come from the
original trusted workflow commit, never from the mutable staged tree. Each fresh
runner fetches only locked dependency payloads into a new private Cargo cache.
Validated service cooldowns survive runner changes as one conservative UTC
not-before deadline (no secret Azure hostname is exported). Every phase process
restores that deadline before work and saves the later persisted/current deadline
on exit, including failure. Checkpoint and resume preserve it between jobs, so
neither a new process nor a fresh runner resets server-requested backoff.

## Completion, retry and publication

After four batches, unexamined commits are reported explicitly and retain the old
cutoff along with failed/deferred candidates. Earlier accepted fixes can still
produce a useful partial maintenance PR. Final build/test/fmt/NSS/available
packaging, metadata/Nix regeneration and clean-tree failures still block it.
Both final cargo-audit and locked, frozen cargo-vet checks run even when the first
audit fails. Findings
or audit execution failures become explicit manual work in the report and PR;
the job can publish a **draft**, with unchecked remediation/rerun tasks, rather
than discard the tested changes. This path does not claim a validated release
or mark the PR ready for review. It creates no exemptions or audit approvals.
Only a run passing both audits can use normal ready-for-review publication.

Publication checks that either the fully validated HEAD or the separately
recorded draft-only HEAD is still the exact clean staged HEAD, and that stable
has not advanced. A fresh validation clears both earlier outcomes before any
checks run. Neither outcome is transferred in checkpoint artifacts. A checkpoint
is never evidence that final gates passed. Maintainers must remediate the listed
audit work and rerun full release validation before approving a draft for release.

Use Actions' **Re-run failed jobs** to resume a failed, pre-publication stage
from its predecessor without repeating successful earlier stages. Reruns keep the original trusted
tooling snapshot; checkpoints from earlier attempts of the same run are allowed,
but another run's state is not. A full new dispatch starts from stable again and
does not automatically trust an abandoned staging branch. Checkpoint artifacts
expire after seven days; after expiration, start a new dispatch. Checkpoint refs
are retained for inspection (no automatic branch deletion in this change).

Each hosted job still has a six-hour hard limit. A persistently unavailable
service or an individually oversized non-backport phase can still fail closed;
this is not a promise that arbitrary backlog or outage sizes will finish. The
bounded backport stages reserve ample time outside their processing budget for
image setup, cleanup, checkpoint push and report upload. Final validation remains
a fresh job and cannot be substituted by earlier builds.

## Revalidating a preserved manual-audit draft

An open maintenance PR, including a manual-audit draft, intentionally blocks new
scheduled or dispatched maintenance for that stable branch. The guard prevents
duplicate PRs and preserves maintainer edits. A workflow rerun resumes its old
checkpoint, not the repaired draft HEAD; do not bypass the guard or close the
draft merely to revalidate it. The standalone `prepare`, `validate` and `report`
commands provide the manual, validation-only path below. They do not publish,
replace the PR branch, or mark the draft ready.

1. Remediate the audit findings on the existing draft branch and push those
   commits. Record its exact repaired HEAD. Normal PR CI is useful but does not
   replace the complete isolated final gates, including cargo-audit.
2. Use an isolated Linux/Docker test runner with Python 3.12, the maintenance
   workflow's outbound allowlist and no publication/Azure credentials. Check out a reviewed,
   immutable `main` revision in `TOOLING_DIR` and that repaired PR HEAD in a
   separate `SOURCE_DIR`. Both paths must be absolute; use a full source clone
   with its own `.git` directory, not a linked worktree. Disable Git hooks in both
   checkouts. Never use tooling or the Dockerfile from the mutable PR checkout.
3. Set `EXPECTED_HEAD` to the repaired 40-character SHA and `TARGET_BRANCH` to
   its stable base. Run the following in Bash. Every attempt creates fresh state,
   image context and a private Cargo cache outside the source checkout. Do not
   copy a workflow's skipped state or checkpoint into this directory, and do not
   run `guard`, `initialize`, `release` or `publish` as part of this validation.

```bash
set -euo pipefail
: "${TOOLING_DIR:?absolute trusted main checkout}"
: "${SOURCE_DIR:?absolute repaired PR checkout}"
: "${EXPECTED_HEAD:?exact repaired PR head SHA}"
: "${TARGET_BRANCH:?stable-3.x or stable-4.x}"
test -z "$(git -C "$TOOLING_DIR" status --porcelain)"
test "$(git -C "$SOURCE_DIR" rev-parse HEAD)" = "$EXPECTED_HEAD"
test -z "$(git -C "$SOURCE_DIR" status --porcelain)"

validation_dir=$(mktemp -d)
mkdir -m 0755 "$validation_dir/cargo" "$validation_dir/image-context"
export MAINTENANCE_PROJECT_CARGO_HOME="$validation_dir/cargo"
export MAINTENANCE_BUILD_IMAGE="himmelblau-stable-maintenance:revalidate-$$"
export MAINTENANCE_TOOLING_COMMIT="$(git -C "$TOOLING_DIR" rev-parse HEAD)"
tool="$TOOLING_DIR/.github/scripts/stable_maintenance.py"
export MAINTENANCE_TOOLING_SHA256="$(sha256sum "$tool" | cut -d ' ' -f 1)"
docker build --file "$TOOLING_DIR/.github/stable-maintenance.Dockerfile" \
  --tag "$MAINTENANCE_BUILD_IMAGE" "$validation_dir/image-context"

python3 "$tool" --repo-dir "$SOURCE_DIR" --state-dir "$validation_dir/state" \
  prepare --branch "$TARGET_BRANCH"
validation_status=0
python3 "$tool" --repo-dir "$SOURCE_DIR" --state-dir "$validation_dir/state" \
  validate --branch "$TARGET_BRANCH" || validation_status=$?
python3 "$tool" --repo-dir "$SOURCE_DIR" --state-dir "$validation_dir/state" \
  report --branch "$TARGET_BRANCH"
test "$validation_status" -eq 0
test "$(git -C "$SOURCE_DIR" rev-parse HEAD)" = "$EXPECTED_HEAD"
test -z "$(git -C "$SOURCE_DIR" status --porcelain)"
python3 - "$validation_dir/state/state.json" "$EXPECTED_HEAD" <<'PY'
import json
import sys
from pathlib import Path

state = json.loads(Path(sys.argv[1]).read_text())
if (state.get("validated_head") != sys.argv[2]
        or state.get("manual_audit_work") or state.get("manual_audit_head")
        or state.get("failed_phase") or state.get("skip")):
    raise SystemExit("Release validation is incomplete; keep the PR in draft")
print(f"All final gates passed for repaired HEAD {sys.argv[2]}")
PY
```

Audit findings intentionally make `validate` return zero with manual work, so
the final state check is mandatory; the process exit code alone is not release
approval. Retain the success output identifying the exact HEAD alongside
`report.md` and `report.json` as validation evidence, not the private state
directory. Before manually marking the existing PR ready, verify
its current remote HEAD still equals `EXPECTED_HEAD`, review the audit remediation
and ensure its stable base is still appropriate. Any later source change requires
fresh full validation. Keep the draft open if a gate fails; the next automated
maintenance run may proceed only after the existing PR is merged or closed.
