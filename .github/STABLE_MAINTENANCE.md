# Stable maintenance behavior

The workflow snapshots trusted tooling from the triggering `main` revision and
stable source separately. Its `backports` phase inventories commits in ancestry
order, then completes one commit before evaluating the next:

1. Classify the actual patch and description as a correction to existing behavior
   or testing CI. A `fix` subject does not authorize a new feature.
2. Evaluate relevance against the evolving stable worktree, including earlier
   accepted backports. Main-only features remain excluded; uncertainty is pending
   review, not an intentional exclusion.
3. Cherry-pick. For conflicts, try at most two AI-proposed adaptations. Models
   return patch data, never commands. Trusted code checks paths, file types,
   application, testing-job boundaries, and obtains a second scope decision.
4. Build the locked workspace. On failure, restore only this attempt and preserve
   earlier accepted commits. Record compiler codes and leave the item pending.
5. Run contained `cargo fmt --all` and amend formatting into the backport commit.
   A formatter failure also rolls back only this attempt.

The final publication gates include a clean locked build, workspace tests,
formatting, available NSS and packaging-generator tests, cargo-audit, cargo-vet,
Cargo.nix regeneration, and a clean worktree. They do not replace distro package
builds, SELinux policy tests, or runtime authentication testing. PRs still require
human review and are never automatically merged.

Only changes confined to the known testing jobs in `.github/workflows/ci.yml`
are considered for CI backports. Workflow triggers, permissions, global settings,
build jobs, package creation and publication stay outside that policy. Mixed
source/protected-CI changes require review. Dependabot's independently validated
pinned-action imports retain their existing policy.

Backport input is bounded to 192 KiB. Generated lockfile and Cargo.nix diffs are
excluded from AI context (not from the original cherry-pick), and large stable
files use explicitly labeled excerpts around patch anchors. Missing context is
not evidence that functionality is absent. AI decisions must record an allowed
reason; uncertain decisions stay pending. Repairs cannot edit generated metadata,
supply-chain policy or automation tooling, and never import prerequisite features
from main.

Azure retries use 5/10-second backoff for other failures. Throttling respects
positive server guidance; missing/zero guidance falls back to a 60/120-second
window plus jitter. Exhausted token quota enforces at least that window. Stable
targets run serially to avoid competing for the shared deployment's quota.
Backoffs remain bounded, and failures remain visible rather than becoming negative
eligibility decisions.

Cargo metadata's `/workspace` manifest paths are mapped to validated host checkout
files before dependency editing. Rejected updates have stage-specific reasons.
Fresh releases remain intentionally quarantined for 252 hours, except for the
existing libhimmelblau and advisory remediation exceptions.

The run summary and 30-day `report.md`/`report.json` artifacts show commit subjects,
applied/adapted fixes, intentional exclusions, pending work, conflict paths and
compiler codes. Raw credentials, model responses and subprocess output are not
uploaded. The artifacts preserve processing order; the displayed table puts
pending work first. The main-through marker retains the old cutoff while any
backport is pending. An existing maintenance PR still blocks another release
proposal until it is handled.

The separate `classify-backports` and `apply-backports` commands remain available
for conservative diagnostics; the scheduled workflow uses the sequential
`backports` command.
