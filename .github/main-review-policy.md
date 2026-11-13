# Main review and automatic merge policy

This policy applies only to PRs targeting `main`. Stable and other branches
keep their existing rules and are never merged by this automation.

| Author | Required current reviews | Automatic merge |
| --- | --- | --- |
| Write, maintain, or admin; or a writer-sponsored AI bot | One successful AI review **or** one authorized human approval | Only for non-sensitive fixes with explicit testing confirmation |
| Outside contributor, including unsponsored bots | Two distinct reviewers, including at least one authorized human | Never; a repository writer merges manually |

Sensitive changes always require an authorized human approval and manual
merging. Outside contributors still need two distinct reviews when touching
sensitive code. CI and conversation-resolution requirements apply to manual
and automatic merges alike. A successful `Review policy` check means manual
review requirements are satisfied, not that automatic merging is authorized.

Authorized humans have repository write access. The author cannot review their
own PR. Two humans qualify for an external PR, as do one human and one AI.
Reviews from the same AI provider count once, including delegated reviews.
All qualifying reviews must cover the current head SHA. New pushes require
fresh review, but merging another PR does not require updating the branch.

Every path requires no unresolved review threads, including outdated ones,
and no outstanding request for changes from an authorized human or trusted
AI. A later comment does not cancel a request for changes; approve again or
dismiss that request. Drafts never merge.

## Sensitive changes

The classifier runs from the policy already on `main`. It examines every
changed file and both names of renames, including deleted files. An incomplete
file list fails the check rather than treating unexamined files as safe.

Human approval and manual merging are required for:

* Core authentication/identity: `src/pam/`, `src/nss/`, `src/daemon/`,
  `src/common/`, and `src/idmap/`.
* Token handling/administration: `src/broker/`, `src/broker-client/`,
  `src/sso/`, and `src/cli/`.
* Policy execution: `src/policies/`.
* **Everything in `.github/`**, including templates, documentation and tests.
* Login configuration: `platform/*/pam-config*`, `platform/*/sshd_config`,
  `src/sshd-config/`, and `scripts/gen_authselect.py`.
* Service privileges: `scripts/gen_servicefiles.py`, `platform/systemd/`,
  and `nix/modules/`.
* Dependency overrides and trust records: `src/overrides/`, `supply-chain/`,
  `scripts/cargo-patch-config.toml`, and `scripts/cargo_vet_review.py`.
* Supporting publication/automation scripts: `scripts/obs_update.py`,
  `scripts/backport.py`, `scripts/fix-bugs.py`,
  `scripts/dependabot_automerge_check.sh`, and `scripts/dependabot_rollup.py`.
* Rust build hooks (`build.rs`), security/authentication dependency changes,
  Cargo manifest edits beyond version bumps, and dependency source/feature/
  build-hook changes in Cargo/Nix/build files.
  Missing patches for those files require a human. Ordinary non-security
  dependency version updates can remain AI-eligible; the diff classifier is
  conservative and may also flag nearby security-dependency context.

`src/selinux/`, experimental `src/orchestrator/`, and `src/collabora/` are
**not** protected runtime directories. Their ordinary code changes remain
AI-eligible; shared build/dependency rules still apply. Other paths are
AI-eligible unless matched by the explicit rules above. This is a review
routing policy, not a claim that all other files are harmless.

## Sponsorship and testing confirmation

Bot authors do not inherit team status from their names, author association,
or claimed owner. A current repository writer can explicitly take responsibility
for an AI companion's PR by posting this entire comment **on the PR**:

```text
/sponsor-ai FULL_40_CHARACTER_HEAD_SHA
```

This applies only to Bot authors and this exact head. It cannot promote an
outside human contributor into the team route. It is not a review approval
and does not replace testing confirmation. A companion using a writer's own
User account follows that account's actual permissions; the automation cannot
identify who operated it.

For a non-sensitive team fix, a writer records that the exact head was tested
and the reported bug is resolved by posting this entire comment on the PR:

```text
/confirm-tested FULL_40_CHARACTER_HEAD_SHA
```

The writer may have tested it themselves, or can attest to another person's
test result by including the acknowledgment's URL:

```text
/confirm-tested FULL_40_CHARACTER_HEAD_SHA https://github.com/himmelblau-idm/himmelblau/issues/123#issuecomment-456
```

The evidence must be a nonempty comment by a User account, on this PR or a
same-repository associated issue. An issue is associated through GitHub's
closing-issue links (for example `Fixes #123`), or its full GitHub issue URL
in the PR description. The evidence URL must use `#issuecomment-ID`; inline
review threads, external repositories and arbitrary websites do not qualify.
The writer is responsible for verifying that the acknowledgment reports actual
successful testing of this head and resolution of the bug. The coordinator
validates provenance, not natural-language meaning. A tester without write
access can supply evidence but cannot issue an effective confirmation command.
Plain “works now” comments, reactions, AI output and CI success alone do not
authorize an automatic merge. Commands do not add review votes.

New pushes invalidate both sponsorship and testing confirmation. Writers can
revoke either on the same head with `/revoke-sponsor FULL_SHA` or
`/revoke-tested FULL_SHA`. The latest surviving authorized command of each
kind wins, ordered by edit/creation time and then comment ID. Deleting a grant
removes that grant; deleting a revocation can expose an earlier grant again.
Removing the evidence comment also invalidates a linked confirmation.
Quoted commands, code blocks, abbreviated SHAs and commands from read-only
users or bots are ignored. Posting a confirmation may cause an immediate
merge if all remaining requirements are met and automatic merging is enabled.

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

1. Require the **Review policy** check, selecting **GitHub Actions** as its
   expected source. Keep `Build`,
   `Test`, `Clippy`, and `Vet Dependencies` required; those four CI names are
   explicitly checked by the coordinator as well.
2. Keep requiring a pull request and the existing CI checks. Set the native
   required approval count to **0**: the custom check implements review counts
   and sensitive-path human requirements.
   Remove conflicting required-human/team/code-owner approval requirements
   only on main if they would independently prevent the AI-only path.
   Do this only after step 1 is in place so main is never left without a
   review gate.
3. Enable **Require conversation resolution before merging** (rulesets call
   this **Require all conversations to be resolved before merging**).
   This also enforces resolution at the actual merge boundary.
4. Uncheck **Require branches to be up to date before merging**. Do not add a
   merge queue or a bypass for the coordinator. Existing protection rules
   and rulesets combine, so check both Settings → Branches and Settings →
   Rules → Rulesets for main. Do not change stable branch rules.
5. In Settings → Secrets and variables → Actions → Variables, create
   `MAIN_REVIEW_POLICY_AUTOMERGE` with value `true`. This activates automatic
   squash merging for eligible, non-sensitive, writer-authored/sponsored,
   testing-confirmed main fixes, including existing ones with those explicit
   attestations. External and sensitive PRs remain manual-only.
   Remove/set it to `false` to stop merging while retaining policy reporting.

Administrators must do the settings changes; the GitHub integration used to
prepare this implementation cannot administer branch protection. Do not lower
native approval requirements until `Review policy` is required. Keep the
repository's currently disabled native GitHub auto-merge switch disabled:
native auto-merge does not implement the additional author, sensitivity and
testing restrictions, because the policy check also permits manual merges.
Other merge bots must likewise not independently merge main PRs under weaker
rules. The coordinator performs the merge itself, with the expected head SHA,
and GitHub enforces branch protections.
It never bypasses a blocked/behind state or updates a PR branch.

## CI and timing

The coordinator checks mandatory CI by GitHub Actions app identity, also
waiting for all other observed checks/statuses on the head or current test
merge. Optional neutral/skipped checks are accepted; the four mandatory jobs
must succeed. Pending, failed, cancelled, or missing mandatory checks block
automatic merging. A successful policy check represents reviews, not CI;
native CI requirements remain separate.

Review submissions wake the coordinator through a read-only workflow, including
fork reviews. PR updates, PR/issue comments, external checks, statuses and completion
of `CI` also wake it. Thread resolution has no GitHub Actions event, so a
five-minute scheduled sweep catches it, other CI completions and missed events.
GitHub can delay scheduled runs. A manual Main review policy workflow dispatch
also re-evaluates all open main PRs. No CI rerun is requested by this workflow.

Automatic merges use `GITHUB_TOKEN`, so they do **not** trigger other workflows
listening for push events, per GitHub's recursion prevention. PR CI has already
passed. If push-triggered publication is added later, use a dedicated GitHub App
with the same scoped permissions instead of a bypass/admin credential.

The check/merge API cannot make review reads and merge atomic. Reviews,
threads, permissions, sponsorship, testing evidence and CI are reloaded before
an automatic merge, followed by a final PR read and expected-head SHA merge.
Native conversation resolution and GitHub's own merge checks narrow the
remaining window. Privileged repo writers can alter Actions checks
or attestations; this policy trusts them, as it trusts their code changes.
Protect policy changes with the normal review process.

Local verification: `node --test .github/scripts/test_review_policy.js`.

