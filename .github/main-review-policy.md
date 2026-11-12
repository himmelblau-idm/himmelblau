# Main review and automatic merge policy

This policy applies only to PRs targeting `main`. Stable and other branches
keep their existing rules and are never merged by this automation.

| Author's current repository permission | Required current reviews |
| --- | --- |
| Write, maintain, or admin | One successful AI review **or** one authorized human approval |
| Everyone else, including bot authors | Two distinct reviewers, including at least one authorized human |

Authorized humans have repository write access. The author cannot review their
own PR. Two humans qualify for an external PR, as do one human and one AI.
Reviews from the same AI provider count once, including delegated reviews.
All qualifying reviews must cover the current head SHA. New pushes require
fresh review, but merging another PR does not require updating the branch.

Every path requires no unresolved review threads, including outdated ones,
and no outstanding request for changes from an authorized human or trusted
AI. A later comment does not cancel a request for changes; approve again or
dismiss that request. Drafts never merge.

## Recognized AI review signals

The coordinator verifies the bot identity and review commit, rather than
counting arbitrary comments mentioning an AI product:

* CodeRabbit: a current-head submitted review, successful `CodeRabbit` check
  from app ID 347564, and its clean summary explicitly naming that head with
  `change_assessment_commit` and saying no actionable comments were generated.
  Failed pre-merge checks do not qualify. A green check alone only means the
  review finished. After resolving findings, request a fresh clean review.
* Copilot: an approving review, or its current `ccr-overview-v2` assessment
  saying `Ready to approve` and `No open issues`. `Needs a closer look` does
  not qualify, even if it says there are no open issues.
* Codex: an approving review, or a commit-bound submitted review headed
  `Codex Review: Didn't find any major issues.` or `Codex Review: No findings.`
  Its top-level clean `Codex Review` comment also qualifies when it explicitly
  identifies the current `Reviewed commit` (at least 10 SHA characters).
  A PR thumbs-up reaction has no reviewed SHA and cannot qualify on its own.

If an AI uses a maintainer's account, submit an **APPROVE** review anchored to
the reviewed head, with one of these on its own line in the body:

```text
<!-- review-policy:ai:codex -->
<!-- review-policy:ai:copilot -->
<!-- review-policy:ai:coderabbit -->
```

Use only the applicable marker. This is a maintainer attestation that the
named AI completed the review successfully. It counts as AI, not human, even
though GitHub displays an approval checkmark. The repository's older wording
`contributing this review as Codex` is also treated as AI. Unmarked approvals
by authorized User accounts count as human; software cannot prove who was
behind an account. Unknown or changed bot output formats fail closed and
require a supported approval or adapter update. Comments and reactions posted
through human accounts do not independently count as AI review.

## Deployment

Merge this PR first. Initially the coordinator reports `Review policy` on the
PR head, but **does not merge anything**. It always runs trusted code from
`main`, never code or artifacts from a PR. It uses the repository's standard
`GITHUB_TOKEN`; no AI API key or new service is needed.

After the workflow has run, configure the rule(s) covering **only `main`**:

1. Keep requiring a pull request and the existing CI checks. Set the native
   required approval count to **0**: the custom check implements both counts.
   Remove conflicting required-human/team/code-owner approval requirements
   only on main if they would independently prevent the AI-only path.
2. Require the **Review policy** check, selecting **GitHub Actions** as its
   expected source. Keep `Build`,
   `Test`, `Clippy`, and `Vet Dependencies` required; those four CI names are
   explicitly checked by the coordinator as well.
3. Enable **Require conversation resolution before merging** (rulesets call
   this **Require all conversations to be resolved before merging**).
   This also enforces resolution at the actual merge boundary.
4. Uncheck **Require branches to be up to date before merging**. Do not add a
   merge queue or a bypass for the coordinator. Existing protection rules
   and rulesets combine, so check both Settings → Branches and Settings →
   Rules → Rulesets for main. Do not change stable branch rules.
5. In Settings → Secrets and variables → Actions → Variables, create
   `MAIN_REVIEW_POLICY_AUTOMERGE` with value `true`. This activates automatic
   squash merging for **all eligible open main PRs**, including existing ones.
   Remove/set it to `false` to stop merging while retaining policy reporting.

Administrators must do the settings changes; the GitHub integration used to
prepare this implementation cannot administer branch protection. Do not lower
native approval requirements until `Review policy` is required. The built-in
GitHub auto-merge switch is unnecessary: the coordinator performs the merge
itself, with the expected head SHA, and GitHub enforces branch protections.
It never bypasses a blocked/behind state or updates a PR branch.

## CI and timing

The coordinator checks mandatory CI by GitHub Actions app identity, also
waiting for all other observed checks/statuses on the head or current test
merge. Optional neutral/skipped checks are accepted; the four mandatory jobs
must succeed. Pending, failed, cancelled, or missing mandatory checks block
automatic merging. A successful policy check represents reviews, not CI;
native CI requirements remain separate.

Review submissions wake the coordinator through a read-only workflow, including
fork reviews. PR updates, bot comments, external checks, statuses and completion
of `CI` also wake it. Thread resolution has no GitHub Actions event, so a
five-minute scheduled sweep catches it, other CI completions and missed events.
GitHub can delay scheduled runs. A manual Main review policy workflow dispatch
also re-evaluates all open main PRs. No CI rerun is requested by this workflow.

Automatic merges use `GITHUB_TOKEN`, so they do **not** trigger other workflows
listening for push events, per GitHub's recursion prevention. PR CI has already
passed. If push-triggered publication is added later, use a dedicated GitHub App
with the same scoped permissions instead of a bypass/admin credential.

The check/merge API cannot make review reads and merge atomic. Current-head
checks, a fresh PR read, native conversation resolution and GitHub's own merge
checks narrow this window. Privileged repo writers can alter Actions checks
or attestations; this policy trusts them, as it trusts their code changes.
Protect policy changes with the normal review process.

Local verification: `node --test .github/scripts/test_review_policy.js`.
