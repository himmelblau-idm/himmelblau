# Collabora bridge validation

This feature is experimental. Mock tests establish adapter behavior, not interoperability with released desktop builds or Microsoft Office save semantics. Issue #1736 remains open.

## Automated fixtures

Run `cargo test -p himmelblau-collabora`, `python3 scripts/test_collabora_packaging.py`, `python3 scripts/test_collabora_distribution_packaging.py`, and `cargo fmt --all -- --check`.

Package lifecycle fixtures mock systemd and user commands to check non-disruptive upgrades, fail-closed removal, absent managers/services, and the unit's write policy. HTTP fixtures also cover route-local body limits, upload authentication before body buffering, navigation when personal OneDrive is unavailable, document creation in OneDrive and SharePoint folders, duplicate names, and safe cleanup of incomplete recovery files.

Distribution fixtures check Arch split-package selection and copying, opt-in installation, cleanup-before-removal, Gentoo USE-gated asset installation, and Nix desktop asset paths. They use staged files and mocked package managers; native distro builds and live login/removal checks remain required.

Additional transfer fixtures cover capped streaming downloads, admission through response completion/disconnect, upload admission before buffering, idle connected-session retention, missing-session errors, and persistent recovery filenames with safe download headers and legacy-copy fallback.

Authentication fixtures cover early token rejection, one read retry, cache clearing after a failed refresh or repeated 401, preserving a newer concurrent bearer, and avoiding automatic replay of writes or sharing-link redemption.

Recovery fixtures also check state-owner exclusion, reclamation of recognized crash temporaries, and preservation of unrelated files, directories, and symlinks during cleanup.

The tests cover malformed endpoint repair, atomic private endpoint replacement, an occupied saved port, missing profiles, private profile storage, preservation of unrelated providers on repair/removal, delegated file/site scopes, SharePoint drive browsing without personal OneDrive, WebSocket authentication, one-shot token replay/wrong-kind/expiry and stale upload revision rejection (including a successful save without a returned eTag), unsupported messages, handshake timeout and connection admission, stale eTags, HTTP 412 at upload-session creation, network/upload failure, recovery failure, bounded recovery, and cleanup after successful retry. The HTTP 412 fixture represents a concurrent edit between the metadata read and conditional session creation. Microsoft and upload endpoints are loopback mocks only under `cfg(test)`; production origin/HTTPS checks remain enforced.

## Required before production release

Use an authorized disposable Microsoft 365 tenant. Never commit bearer tokens, account/tenant identifiers, unsanitized traces, or document contents. Record exact Collabora package version/build and native/Flatpak variant for every result; no released version range is currently certified.

| Area | Checks | Required outcome |
| --- | --- | --- |
| Provisioning | Existing native/Flatpak profile; first launch; profile locked/recreated; upgrade | Only existing installed profiles change; unrelated providers survive; registration retries after closing Collabora |
| Privacy | Two local users; permissive pre-existing profile and endpoint modes | Other UID cannot read bootstrap state, list documents, or use capabilities |
| Startup | Corrupt endpoint; occupied saved port; crash while persisting state | Service repairs state and provider endpoint; endpoint is always complete JSON and private |
| Open/edit/save | DOCX/XLSX/PPTX from OneDrive and SharePoint; share link; shared drive without personal OneDrive | Stock desktop intercepts editor navigation; saved edits reopen correctly |
| Create/open/save | New Word, Excel, and PowerPoint files in OneDrive and SharePoint folders; duplicate name; read-only folder | Each new file opens immediately, saves and reopens; duplicate names remain untouched; denied creation reports an error |
| Scopes/broker | File-only token; Sites consent; denied consent; broker hangs | File browsing remains available; unsupported site search hidden; broker calls time out |
| Conflicts | Office/web edit before Save; during session creation; during chunk upload | Remote changes are never silently overwritten; local edits are recoverable; document remains open on recovery failure |
| Upload failure | Interrupted chunk/session; expired upload URL; offline; empty file; deleted/moved item | Failure is explicit; retry behavior verified; edited copy downloadable |
| Recovery | Repeated autosaves; restart/logout; quota full; unwritable/full disk; successful retry | Latest per-session copy replaces atomically; storage bounded; success only after durable write; no false preservation claim |
| Removal | Native and Flatpak, active/logged-out user, unrelated provider, locked profile, custom XDG paths | Only Himmelblau provider/state removed; locked cleanup reports failure; unrelated providers remain |
| Protocol compatibility | Each candidate release; malformed/unknown frames; semantic changes using same names | Unsupported shapes fail explicitly; establish actual release range before rollout |

Capture the authorized Office/OneDrive protocol trace matrix from #1736 and compare discovery, scopes, small/resumable uploads, versions, checkout, concurrent commits, retries and failure recovery against the adapter. In particular, mock conditional-session tests do not prove that a later Graph upload-session commit protects against concurrent changes during upload. Socket activation, negotiated versions, and the trace/real-tenant matrix remain release work.
