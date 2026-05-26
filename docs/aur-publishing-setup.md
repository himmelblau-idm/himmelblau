# AUR Publishing — Maintainer Setup Guide

This guide is for the human (or humans) who own the
[himmelblau AUR package](https://aur.archlinux.org/packages/himmelblau). It
covers the one-time secret setup, the moving parts of the publish workflow,
how to do a no-op dry run before a real release, how to validate the package
locally, and what to do when something goes sideways.

If you have never published to the AUR before, work through every section in
order at least once. If you are the existing maintainer doing a routine
release, the **Running a dry run** and **Troubleshooting** sections are
probably what you want.

## Overview

The publishing pipeline takes an upstream `himmelblau` release tag and pushes
an updated package recipe to the AUR. It is intentionally small: a single
GitHub Actions workflow renders a hand-edited template, then hands the result
off to a community-maintained deploy action for the SSH and git work. There
is no bespoke generator script, no committed `PKGBUILD`, and no committed
`.SRCINFO`.

Three files do all of the work:

| File | Purpose |
|------|---------|
| `.github/workflows/aur-publish.yml` | Trigger handling, version resolution, tarball SHA-256, PKGBUILD render, hand-off to the deploy action |
| `platform/arch/PKGBUILD.in` | Hand-edited PKGBUILD template with two sentinel substitutions (`@PKGVER@` and `@SHA256@`) |
| `platform/arch/himmelblau.install` | pacman install scriptlet (post-install / upgrade / remove messages) |

The two design decisions worth understanding before you change anything:

- **SSH, git clone, commit, push, and `.SRCINFO` generation are delegated to
  a SHA-pinned third-party action** rather than hand-rolled in shell. This
  shrinks the attack surface, removes ~80 lines of bespoke bash, and gets
  `.SRCINFO` regeneration for free. The action runs in an Arch base-devel
  container, so namcap and makepkg are already on PATH for it.
- **The PKGBUILD lives in the repo as a template, not as the output of a
  generator script.** AUR convention is to read the PKGBUILD top-to-bottom;
  reviewers (including Trusted Users who occasionally adopt orphaned
  packages) expect that. Two sentinels — version and source tarball SHA —
  are substituted at publish time; everything else is hand-edited.

## Prerequisites

Before you can publish anything you need:

- **GitHub repo admin** on the fork that owns the workflow — you need it to
  add the SSH secret under `Settings → Secrets and variables → Actions`.
- **An AUR account** at <https://aur.archlinux.org/register>. Pick a stable
  username; it ends up in the package's git history forever.
- **Maintainer status on the `himmelblau` AUR package.** If the package is
  orphaned or owned by someone else, request adoption via the AUR web UI
  (`Package Actions → Adopt Package`). If a contested adoption is needed,
  follow the [Trusted User process](https://wiki.archlinux.org/title/AUR_Trusted_User_Guidelines).
- **A local Arch toolchain for validation**: `makepkg` from `pacman` and
  either `podman` or Docker Desktop. macOS hosts run the validation inside
  a container — no native Arch needed.

## One-time setup

Everything here happens exactly once per maintainer. After it is done the
workflow runs unattended on every release tag.

### 1. Generate a dedicated Ed25519 SSH key

Do not reuse your personal SSH key for AUR publishing. A workflow-scoped
key is rotatable, revocable, and audit-trail-friendly.

```bash
ssh-keygen -t ed25519 -C "himmelblau-aur-publish" -f ~/.ssh/aur_himmelblau -N ""
```

This produces two files:

- `~/.ssh/aur_himmelblau` — the private key (goes into a GitHub secret)
- `~/.ssh/aur_himmelblau.pub` — the public key (goes into your AUR account)

### 2. Register the public key with the AUR

Open <https://aur.archlinux.org/account/> while signed in, click your
username, and paste the contents of `~/.ssh/aur_himmelblau.pub` into the
**SSH Public Key** field. Save. The AUR accepts multiple keys, so you can
keep your personal key registered alongside this one.

### 3. Store the private key as a GitHub Actions secret

In the GitHub repo, go to `Settings → Secrets and variables → Actions →
New repository secret` and create:

| Name | Value |
|------|-------|
| `AUR_SSH_PRIVATE_KEY` | The full contents of `~/.ssh/aur_himmelblau`, including the `-----BEGIN OPENSSH PRIVATE KEY-----` and `-----END OPENSSH PRIVATE KEY-----` lines and the trailing newline |

This is the only secret the workflow needs. There is no AUR username, no
AUR password, no GitHub PAT involved in the publish path.

### 4. Verify the key works

From your workstation, before you trust the workflow with it:

```bash
ssh -i ~/.ssh/aur_himmelblau aur@aur.archlinux.org help
```

Expected output is a short usage banner ending in `Welcome to AUR, <user>!`.
If you get `Permission denied (publickey)`, the key did not register
correctly — recheck step 2.

## How the workflow runs

The workflow lives at `.github/workflows/aur-publish.yml`. It fires on three
trigger sources, resolves the version it should publish, computes the source
tarball hash, renders the PKGBUILD from the template, sanity-checks the
render, and then either hands off to the deploy action or stops short for a
dry run. A `concurrency` group named `aur-publish` prevents two pushes from
racing each other if tags land back-to-back.

### Triggers

Any one of these starts a run:

- **Tag push** matching `N.N.N` or `N.N.N-suffix` (the production case —
  fired automatically by the existing "Rust Version Tagging" workflow).
- **GitHub release publish** (catches the manual republish edge case).
- **`workflow_dispatch`** from the Actions tab, with optional `version` and
  `dry_run` inputs (the case you will use for testing and for the rare
  out-of-band republish).

### Version resolution

The workflow picks a version using this priority order:

1. `workflow_dispatch` input `version` (stripped of a leading `v` if
   present) — manual override always wins.
2. The triggering tag name, stripped of a leading `v` — used on tag pushes.
3. The GitHub API's "latest release" `tagName`, stripped of a leading `v` —
   used on release events and as the safe fallback.

This decoupling matters: a pre-release tag should not silently push a real
AUR update, and the API-derived fallback avoids 404s on tarball fetch when
a triggering tag is not yet attached to a published release.

### Source tarball SHA-256

The workflow downloads the GitHub-generated source tarball and hashes it.
It tries the bare tag form first (`3.1.5`) and falls back to the
`v`-prefixed form (`v3.1.5`) — whichever exists. The URL the workflow
fetches **must exactly match** the `source=` URL the rendered PKGBUILD
will declare; this is enforced implicitly by both being derived from the
same `VERSION` value.

### PKGBUILD render

Two `sed` substitutions, no Python, no generator:

```bash
sed -e "s|@PKGVER@|${VERSION}|g" \
    -e "s|@SHA256@|${SHA256}|g" \
    platform/arch/PKGBUILD.in > aur-work/PKGBUILD
cp platform/arch/himmelblau.install aur-work/himmelblau.install
```

The rendered PKGBUILD is dumped to the step log every run, so you can scroll
back through any run and read exactly what was about to be published.

### Hand-off to the deploy action

The pinned deploy action takes over from here. Inside an
`archlinux:base-devel` container it:

- writes `AUR_SSH_PRIVATE_KEY` to disk with correct permissions
- does the `ssh-keyscan` against `aur.archlinux.org` (Ed25519 only — we
  pass `ssh_keyscan_types: ed25519`)
- clones `ssh://aur@aur.archlinux.org/himmelblau.git`
- copies the rendered `PKGBUILD` and the install scriptlet in
- runs `makepkg --printsrcinfo > .SRCINFO`
- commits with the message `Update to <version>` as the configured author
- pushes to the AUR

The action is SHA-pinned in the workflow file. Dependabot will open version
bumps; review them like any other action bump.

## Running a dry run

Do this before every real release. It costs about a minute of CI time and
catches PKGBUILD regressions before they reach the AUR.

1. Open the GitHub repo's **Actions** tab.
2. Pick **Publish AUR Package** from the workflow list.
3. Click **Run workflow** (the dropdown on the right).
4. Set **`dry_run`** to `true`. Optionally set **`version`** to a specific
   string (e.g. `3.1.5`) to test rendering for an older release without
   waiting for a tag.
5. Run it.

The workflow will resolve the version, compute the SHA-256, render the
PKGBUILD, validate it, and **skip** the deploy step. The dry-run summary
step prints the resolved version and SHA-256 as a notice. Read the
rendered PKGBUILD in the "Render PKGBUILD from PKGBUILD.in" step output
and confirm:

- `pkgver=` is the version you expected
- `sha256sums=('…')` is a real 64-character hex string (not `SKIP`, not empty)
- `source=` URL contains the right tag form
- nothing else has drifted from what `cat platform/arch/PKGBUILD.in` shows

## Local validation

You do not need credentials to validate a PKGBUILD; everything below runs
without touching the AUR. There are two ways to do this: a wrapper script
in `platform/arch/test/`, and a manual podman one-liner if the script is
unavailable.

> **TODO:** the dedicated wrapper script under `platform/arch/test/` is
> being delivered by a sibling change. Once it lands, the canonical local
> validation flow is to run that script — it standardizes the container
> image, sandbox workaround, namcap invocation, and `makepkg --printsrcinfo`
> in one command. Until then, use the manual flow below.

### Manual podman flow

This is the fallback that works today on any host with `podman` (or
Docker Desktop with `docker` aliased to `podman`-equivalent invocation).
It uses the literal hash `SKIP` to bypass the integrity check — that is
fine for linting metadata, **never** for a real build.

```bash
podman run --rm --platform linux/amd64 \
  -v "$(pwd):/src:ro" \
  archlinux:base-devel bash -c '
    # pacman 6.1+ sandbox segfaults under rootless podman; enable the workaround.
    sed -i "s/^#DisableSandboxSyscalls$/DisableSandboxSyscalls/" /etc/pacman.conf
    pacman -Sy --noconfirm namcap
    cd /tmp
    cp /src/platform/arch/PKGBUILD.in PKGBUILD
    cp /src/platform/arch/himmelblau.install .
    sed -i -e "s|@PKGVER@|3.1.5|g" -e "s|@SHA256@|SKIP|g" PKGBUILD
    namcap PKGBUILD
    useradd -m builder
    chown builder:builder PKGBUILD himmelblau.install
    su builder -c "cd /tmp && makepkg --printsrcinfo"
'
```

`--platform linux/amd64` is only needed on Apple Silicon and other
non-x86_64 hosts. Drop it on a native x86_64 Linux host.

## Troubleshooting

The list below is grouped by the symptom you will actually see.

### "no such file" pushing to `ssh://aur@aur.archlinux.org/himmelblau.git`

The AUR package has not been claimed yet under this account. The first
successful push from this workflow creates the AUR repo as a side effect;
the deploy action handles that case. If you genuinely cannot push, confirm
**maintainer status** in the AUR web UI for the package — your SSH key
must belong to the listed maintainer or a co-maintainer.

### SHA-256 mismatch between the workflow and AUR users

GitHub very occasionally regenerates a source tarball (header changes,
infrastructure migrations), which changes its checksum. If a user reports
a checksum mismatch shortly after publish, rerun the workflow against the
same tag — the recomputed SHA will be picked up and pushed.

### Tarball 404 during the SHA-256 step

The release tag exists in git but has not been published as a GitHub
Release yet, **or** the tag form on GitHub does not match what the
workflow tried. Confirm the tag is visible at
`https://github.com/<owner>/<repo>/releases/tag/<version>` and that the
`source=` URL in the rendered PKGBUILD is reachable from a browser.

### `pacman` segfault inside the local podman run

This is the `DisableSandboxSyscalls` issue. Rootless podman blocks one of
the seccomp syscalls pacman 6.1+ uses for its build sandbox. The fix is
already baked into the manual flow above:

```bash
sed -i "s/^#DisableSandboxSyscalls$/DisableSandboxSyscalls/" /etc/pacman.conf
```

It is harmless inside the throwaway container; do not apply it on a real
Arch system.

### A slop-guard auto-close on an upstream PR (contributor-side)

If you open a PR to **upstream himmelblau** that describes this workflow,
write the PR body in plain, descriptive English. There is an upstream
canary in `.github/scripts/slop-checks.js` (wired up via
`pr-slop-guard.yml`) that auto-closes any PR whose body contains a
specific marker word the slop-guard treats as an AI-generated tell. Do
not paste that marker into your PR body, your commit messages, or your
issue templates. This is unrelated to AUR publishing itself; it only
bites when you are upstreaming changes.

## Rotating the SSH key

Treat the publish key as rotatable. A clean rotation is:

1. Generate a new keypair with a fresh comment, e.g.
   `ssh-keygen -t ed25519 -C "himmelblau-aur-publish-2026q3" -f ~/.ssh/aur_himmelblau_new -N ""`.
2. Add the **new public key** to your AUR account alongside the old one.
3. Replace the value of the `AUR_SSH_PRIVATE_KEY` GitHub secret with the
   new private key.
4. Run the workflow with `dry_run: true` to confirm the render path is
   healthy (this does not exercise the AUR push, but proves the workflow
   plumbing is intact).
5. Run a real publish — either by cutting a routine release tag or by
   dispatching the workflow with an explicit existing `version` (the
   resulting "no-op" push will still authenticate against the AUR and
   confirm the new key works end-to-end).
6. Remove the **old public key** from your AUR account.
7. Delete the old local keypair.

Rotate at least annually, and immediately if you suspect the secret has
leaked (a leaked workflow log, a compromised workstation, etc.).
