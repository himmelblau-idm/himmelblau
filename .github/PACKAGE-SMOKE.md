# Stable package smoke tests

`package-smoke.yml` runs only on PRs targeting `stable-2.x`, `stable-3.x`, or
`stable-4.x`. It does not run on `main` PRs, pushes, or manual dispatches.
The two x86_64 targets are **Ubuntu 26.04** and **Fedora 44**; there is no SLE
registration or repository secret requirement.

Each job builds packages from the PR merge checkout using that checkout's
packaging generator. Older stable branches without these distro entries reuse
their Ubuntu 24.04/Fedora 43 recipe with the requested image substituted in
memory. No source packaging files are changed. The built daemon and NSS packages
are installed with the native package manager in a clean runtime container.

Rootful Podman boots real systemd as PID 1 using a privileged, disposable runner
container with private cgroups and runtime tmpfs mounts. No service overrides
are supplied. The probe uses software-backed keys without enrollment or login,
starts the daemon/tasks service, checks `aad-tool status` for `working!`, rejects
automatic restarts, and exercises restart and stop/start. Diagnostics are
uploaded on failure; container cleanup runs even if a step fails.

This is a deliberately small regression check, not full distro certification.
It does **not** test upgrades, NSS tenant lookups, authentication, hardware TPMs,
host SELinux enforcement, immutable systems, other distros, or ARM. A passing
container test does not establish that all host integration works.

## Rollout and validation

Merge the CI-only change into `main` and backport the same five files to the
stable branches to activate their PR checks. The harness is self-contained; it
does not need release-publishing helpers. Do not require these checks on `main`.
No branch-protection settings are changed by this PR.

Cheap local validation:

```sh
python3 .github/scripts/test_package_smoke.py
python3 -m py_compile .github/scripts/package_smoke.py .github/scripts/package_smoke_guest.py
```

Full smoke runs require a disposable Linux x86_64 host with Docker and rootful
Podman. They execute candidate package scripts and should not run on a personal
workstation. CI performs the expensive runs only for stable-targeted PRs.
