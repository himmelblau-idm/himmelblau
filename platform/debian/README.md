# Debian and Ubuntu PAM profiles

Debian builds use `platform/debian/pam-config`, which enables the
`mfa_poll_prompt` workaround for OpenSSH PAM message buffering. Ubuntu ships
an OpenSSH fix and must not receive this extra prompt; its unchanged profile
is `platform/ubuntu/pam-config`.

This is a downstream packaging distinction, not an OpenSSH version cutoff.
The upstream fix (openssh/openssh-portable#452) remains unmerged as of
2026-10-22. Revisit the Debian default when Debian ships the fix; do not
assume that a newer upstream version includes it.

Both profiles install as `/usr/share/pam-configs/himmelblau`. The package's
existing `pam-auth-update` invocation generates the common PAM stack. The
account, password, session, and unseal configuration is shared unchanged.
The runtime service filter (`mfa_poll_prompt_services`, default `ssh,cockpit`)
still applies to the Debian workaround, but is not a substitute for choosing
the correct distribution profile.

The Dockerfile generator selects `cargo deb --variant=debian` only for the
Debian PAM package, on both amd64 and arm64. Ubuntu targets, including those
selected for Linux Mint by `make`, retain the default metadata/profile.
Direct `cargo deb -p pam_himmelblau` builds also retain the no-workaround
profile; use `--variant=debian` when building for Debian. Other derivatives
are not automatically opted into the workaround and should select the
appropriate profile for their OpenSSH build. The variant preserves the
`pam-himmelblau` package name and substitutes only the primary PAM profile.

Run the source/packaging selection regressions with:

```sh
python3 -m unittest scripts/test_gen_dockerfiles.py -v
```

These tests validate the generated package commands and asset selection,
not a native package build or a live PAM login. Before release, build the
Debian and Ubuntu package targets and inspect the installed profile and the
generated `common-auth` entry on each. Keep an authenticated administrator
session open when testing. Run `pam-auth-update` normally, without `--force`,
and verify SSH number matching, local console/GDM authentication, and a
subsequent normal `pam-auth-update` run. Ubuntu should not gain the polling
prompt; Debian should display its MFA number before the challenge expires.

Background: https://github.com/himmelblau-idm/himmelblau/issues/1890#issuecomment-6350382578
