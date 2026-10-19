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

Use Actions' **Re-run failed jobs** to resume a failed stage from its predecessor
without repeating successful earlier stages. Reruns keep the original trusted
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
