# `platform/arch/test/` — local AUR PKGBUILD validation

A reusable [podman]-based harness that lints (and optionally builds) the
rendered PKGBUILD inside an `archlinux:base-devel` container. The intent is
that any maintainer can validate a PKGBUILD.in change locally with one
command, without remembering the (multi-line) container incantation.

This is the local equivalent of the smoke test that
`.github/workflows/aur-publish.yml` runs in CI. **No AUR credentials are
required**; the harness is read-only against this repo and never pushes
anything anywhere.

## Quick start

```bash
# Lint mode — ~30s under qemu on Apple Silicon, ~10s on x86_64 Linux.
# Renders PKGBUILD with sha256=SKIP, then runs bash -n, namcap, and
# makepkg --printsrcinfo. Version defaults to the latest local git tag.
./platform/arch/test/lint.sh

# Pin a specific upstream version (any tag in the repo).
./platform/arch/test/lint.sh --version 3.1.5

# Full build mode — 20–40 min under qemu, 5–10 min native.
# Fetches the upstream tarball, computes the real sha256, runs makepkg -s
# end-to-end, and runs namcap on the produced .pkg.tar.zst (catches
# install-path issues that PKGBUILD-only linting can't see).
./platform/arch/test/lint.sh --build
./platform/arch/test/lint.sh --build --version 3.1.5

./platform/arch/test/lint.sh --help
```

## Exit codes & PASS/FAIL semantics

The script exits non-zero on **any** of:

- missing `@PKGVER@` / `@SHA256@` sentinels on the canonical definition lines
  in `PKGBUILD.in` (silent template breakage is the failure mode you most
  want to catch)
- `bash -n PKGBUILD` syntax error
- a single `W:` (warning) or `E:` (error) line from `namcap`
- non-zero exit from `makepkg --printsrcinfo` (lint mode) or `makepkg -s`
  (build mode)
- `namcap` warnings/errors on the built `.pkg.tar.zst` (build mode)

A summary line — `PASS — <mode> mode, version X.Y.Z` or `FAIL — …` — is
always printed last, after the dashed separator.

## Requirements

| Tool | Version | Notes |
|------|---------|-------|
| `podman` | any recent | `docker` would work too with a small edit; the script standardizes on podman to match what most Arch maintainers already use |
| `bash` | 4+ | for `${BASH_SOURCE[0]}` and `[[ ]]` |
| `git` | any | only used to look up the latest tag when `--version` is omitted |

The container image (`archlinux:base-devel`) is pulled on first run.

## Environment caveats (read these before debugging)

1. **Apple Silicon (`arm64`) hosts** auto-emulate `linux/amd64` via qemu.
   The script detects this from `uname -m` and adds `--platform linux/amd64`
   to the `podman run` invocation. Lint mode under qemu is ~30s; build mode
   is 20–40 min. There is nothing wrong with your laptop.

2. **`pacman` 6.1+ segfaults under rootless podman.** The fix — `sed`-ing
   `DisableSandboxSyscalls` on in `/etc/pacman.conf` *before* the first
   `pacman -Sy` — is baked into the in-container script. If pacman ever
   starts failing inside the container, check whether the upstream image
   tightened the default sandbox again.

3. **`makepkg` refuses to run as root.** The in-container script `useradd`s
   a `builder` user, `chown`s the work dir to them, and `su`s for the
   actual build. Build mode requires the container to have outbound
   internet access (tarball fetch + `cargo fetch`); rootless podman on
   macOS and Linux defaults to slirp4netns, which is fine.

## Design notes

- **Single bash file, under 200 lines.** No YAML config, no Python helper,
  no plugin system. Adding any of those would make the harness harder to
  audit than the thing it's supposed to validate.
- **Repo is mounted `:ro`.** The container cannot mutate anything in the
  worktree; all scratch lives in `/work` inside the container and dies with
  the container.
- **Lint mode uses `sha256sums=SKIP`** so it can run offline and in seconds.
  Build mode fetches the real tarball and verifies the real sha256 — that's
  the only place a checksum mismatch can be caught locally.
- **`namcap` warnings are treated as failures.** `namcap` exits 0 even
  when it prints `W:` lines; the script greps its output to enforce this.
  If a warning is genuinely benign, fix the PKGBUILD, don't soften the
  harness.

## When to extend this

- **Add a new lint step?** Add a line to the `CONTAINER_SCRIPT` heredoc.
  Keep it shell, keep it idempotent.
- **Test a different distro or builder?** Don't add a flag to this script;
  copy it to a sibling (`platform/<distro>/test/lint.sh`). One script per
  packaging target keeps each one readable.
- **Run this in CI?** Already shape-compatible — see
  `.github/workflows/aur-validate.yml`, which invokes this exact script
  on every push to `aur/**` branches.

[podman]: https://podman.io/
