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

Himmelblau welcomes contributions created with the assistance of AI tools, including coding assistants, chatbots, code-completion systems, and autonomous coding agents.

AI tools are considered development aids, similar to compilers, debuggers, IDEs, and static analysis tools. Their use is permitted and encouraged where they improve contributor productivity.

### Contributor responsibility

Regardless of how a contribution is created, the human contributor remains fully responsible for the submitted work.

Before submitting a contribution, contributors must:

- Review all generated code.
- Understand how the code works.
- Verify that the implementation is correct.
- Test the changes appropriately.
- Ensure that the contribution complies with the project's licensing requirements.
- Be prepared to explain and maintain the submitted code.

Contributors must not submit code that they do not understand.

### Disclosure

When AI tools materially contribute to a change, contributors **MUST** disclose this using an `Assisted-by:` trailer in the commit message.

Examples:

```text
Signed-off-by: Jane Doe <jane@example.com>
Assisted-by: Claude Code
```

```text
Signed-off-by: Jane Doe <jane@example.com>
Assisted-by: GitHub Copilot
Assisted-by: ChatGPT
```

```text
Signed-off-by: Jane Doe <jane@example.com>
Assisted-by: OpenAI Codex
```

Model names are optional. The tool name is sufficient. Multiple tools may be listed when applicable.

Disclosure is intended to improve review transparency and help maintainers apply appropriate scrutiny during code review. Disclosure does not imply lower quality, nor does it automatically affect acceptance decisions.

### Maintainer review

Maintainers may request additional explanation, testing, or design justification for any contribution, whether AI-assisted or not.

Maintainers may reject contributions when:

- The submitter cannot adequately explain the implementation.
- The code lacks sufficient testing or validation.
- The change introduces unnecessary complexity.
- The origin or licensing status of the contribution cannot be reasonably established.

These standards apply equally to human-written and AI-assisted code.

### Low-signal bulk submissions

Using AI to produce feature implementations without prior [enhancement discussion](https://github.com/himmelblau-idm/himmelblau/issues) does not satisfy project process requirements. Discussing proposed changes before implementation remains mandatory for features and large behavior changes, regardless of how the code is written.

## Review and closure policy

Small PRs that follow these guidelines will be reviewed by team members.

Large PRs from external contributors may be automatically closed without review by the triage workflow. Current default closure thresholds include PRs with more than 10 commits or more than 5000 changed lines.

Automatic closure is not a permanent rejection. Large changes might still be acceptable, but they must be discussed with the team first to reopen or re-scope.

## Contact

- Matrix: https://matrix.to/#/#himmelblau:matrix.org
- Issues/Enhancements: https://github.com/himmelblau-idm/himmelblau/issues
