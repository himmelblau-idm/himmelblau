# Himmelblau Contributor Policy

This document sets clear expectations for contribution quality and reviewability.

## Core expectations

- PRs should be small and focused.
- Fix one small thing at a time.
- If you are fixing many independent issues, open many small PRs (for example, 20 fixes means 20 PRs).
- Every commit must have a clear commit message and a `Signed-off-by:` trailer.
- Changes must be tested and the tests must be described in the PR.

## Who should contribute what

Contributors of all backgrounds are welcome. However, if software engineering is not your day-to-day trade or you're new to the project, please start with small bug fixes, documentation updates, or focused cleanup work.

New features and broad refactors usually require prior discussion with the team before implementation.

AI-generated or AI-assisted code is not an alternative to opening an [enhancement request](https://github.com/himmelblau-idm/himmelblau/issues). If the work is a feature or large behavior change, discuss first.

## Contribution steps

1. Pick one small, concrete problem.
2. Check whether there is an existing [issue or enhancement request](https://github.com/himmelblau-idm/himmelblau/issues).
3. If adding a feature or doing a large behavior change, discuss first in Matrix or open an enhancement issue.
4. Implement only that scoped change.
5. Test on a real test VM and record exact steps/results.
6. Build/run relevant automated checks (`make test`, distro package target, `make test-selinux` when applicable).
7. Write clear commits with `Signed-off-by:` on each commit.
8. Open a PR with complete context (see required PR content below).

## Required PR content

Each PR description must include:

- what single problem this PR fixes;
- exact manual test steps and observed results;
- distro name and version used for testing;
- relevant automated checks run, or why a check was not run;
- packaging/runtime impact when touching system integration (systemd, PAM/NSS/authselect, SELinux/AppArmor, filesystem paths, credentials);
- links to related issue/enhancement/discussion.

If generated files are involved, update generator/template sources, not only generated output.

## AI-assisted contributions

AI assistance is allowed, but responsibility remains with the human submitter.

If you use AI, you must:

- review and understand every changed line;
- verify the change with real tests;
- ensure PR text is repository-specific and technically accurate;
- disclose significant AI assistance in the PR description.

Low-signal bulk submissions are not acceptable.

Using AI to produce a feature implementation without prior [enhancement discussion](https://github.com/himmelblau-idm/himmelblau/issues) does not satisfy project process requirements.

## Review and closure policy

Small PRs that follow these guidelines will be reviewed by team members.

Large PRs from external contributors may be automatically closed without review by the triage workflow. Current default closure thresholds include PRs with more than 10 commits or more than 5000 changed lines.

Automatic closure is not a permanent rejection. Large changes might still be acceptable, but they must be discussed with the team first to reopen or re-scope.

## Contact

- Matrix: https://matrix.to/#/#himmelblau:matrix.org
- Issues/Enhancements: https://github.com/himmelblau-idm/himmelblau/issues
