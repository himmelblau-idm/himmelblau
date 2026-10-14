# Himmelblau Collabora bridge (experimental)

`himmelblau-collabora` is an experimental precursor to [#1736](https://github.com/himmelblau-idm/himmelblau/issues/1736), not completion of that issue. It is a separate workspace package. It uses the signed-in user's Himmelblau identity broker to request a delegated Microsoft Graph token under the public Microsoft Office client ID. The existing `o365` package remains in place.

At desktop login, a user service binds an address on `127.0.0.1`, registers a **Microsoft 365** tile in Collabora's current Qt WebEngine cloud list, and serves a local picker. The picker calls Graph for OneDrive files, SharePoint sites and libraries, shared file search, and sharing links. It caches the broker's Graph token until shortly before expiry so browsing and saving do not repeatedly request a token. When a file is opened, Collabora's current `cool.html` remote document bridge exchanges document bytes through `/co/collab`. Saves use Graph upload sessions and preserve failed uploads in the user's state directory.

The picker appears after **Open → Other Microsoft 365** in Collabora. It has Office-style locations, drive search, folder breadcrumbs, and a file details pane. Select a file once to inspect it, then double-click it, press Enter, or use **Open** to launch it. In a OneDrive or SharePoint folder, expand **New document**, choose Word, Excel, or PowerPoint, and enter a name without the extension to create and open a cloud document. The pane contains the existing file actions. SharePoint sites and shared files remain search-based, and a sharing link can be opened from any location.

Registration updates only the `coda.cloudProviders` localStorage value in Collabora's profile. It preserves other entries. The Flatpak profile lives under `~/.var/app/com.collaboraoffice.Office/config/Collabora Office`; the native profile uses the user's XDG config directory. Collabora holds a lock on this database while running, so an installation or upgrade during an open Collabora session appears after the next launch. The Flatpak needs its existing network permission to reach loopback; the add-on does not install Collabora or request a sandbox override.

DEB/RPM package installation starts the bridge in active user sessions. Upgrades leave an already-running bridge in place so open documents keep their in-memory sessions. Save and close all bridge documents before running `systemctl --user restart himmelblau-collabora.service` to use the updated binary. Otherwise, it takes effect when the bridge next starts. The same restart procedure applies when updating the binary outside the package manager.

The bridge also writes a private diagnostic log to `~/.local/state/himmelblau-collabora/bridge.log` (or `$XDG_STATE_HOME/himmelblau-collabora/bridge.log`). It keeps one rotated `bridge.log.old` file and limits each to about 5 MiB. To watch save activity without journal access, run `tail -F ~/.local/state/himmelblau-collabora/bridge.log` after restarting the updated service.

The bridge uses local editing with a Graph upload on Save. It does not provide the `/cool/ws` editor server required by Collabora's real-time collaborative editing mode; the bridge therefore does not advertise the current user as another editor. The picker offers a cloud **Save a copy** command for the latest saved version. It does not capture unsaved editor changes from Collabora's native Save As dialog. Version history is read-only in this stage. New files use bundled nonempty OOXML documents; empty document upload through the upload-session path is not implemented. These cases and the conditional-save behavior must be checked before release.

The protocol choices are based on [Microsoft Graph driveItem upload-session documentation](https://learn.microsoft.com/en-us/graph/api/driveitem-createuploadsession), [driveItem search](https://learn.microsoft.com/en-us/graph/api/driveitem-search), [sharing links](https://learn.microsoft.com/en-us/graph/api/shares-get), [driveItem versions](https://learn.microsoft.com/en-us/graph/api/driveitem-list-versions), [Collabora's public cloud-provider implementation](https://github.com/CollaboraOnline/online.mirror/blob/7ddebab0ef71e249941ff21d2c8e4fbefa474499/browser/src/control/Control.BackstageView.ts), and [Chromium's localStorage schema](https://chromium.googlesource.com/chromium/src/+/dd8d5985e4b1dc04142c94984d0654f4a3339298/components/services/storage/dom_storage/local_storage_impl.cc). No existing Windows and O365 packet trace was used.


## Compatibility and service scope

The desktop protocol fixture is pinned to Collabora's [IntegratorFilePicker.cpp](https://github.com/CollaboraOnline/online.mirror/blob/c0b5f33d523f7baf384b54237db27240b4432d8c/qt/IntegratorFilePicker.cpp) and [global.js](https://github.com/CollaboraOnline/online.mirror/blob/c0b5f33d523f7baf384b54237db27240b4432d8c/browser/js/global.js). The picker intercepts navigation containing `WOPISrc` and `access_token`, cancels that HTTP navigation, and loads its bundled desktop editor. The bridge's `/browser/dist/cool.html` redirect is therefore an interception signal; it does not require hosting editor assets. Ordinary browsers and Collabora Online are not supported consumers of this redirect.

That client starts `/co/collab` with `access_token <capability>` and does not send a protocol or product version. Adding a mandatory invented version frame would break the unmodified client. This bridge recognizes only the documented message shapes, returns an explicit error and closes on an unsupported message or stream, bounds the initial handshake to five seconds, and admits at most 64 WebSocket connections. This is not product-version negotiation: no released Collabora version range has been certified. Supported-release testing and upstream version/capability negotiation remain requirements of #1736.

Document downloads stream through a 250 MB cap with at most four active downloads. One upload or Save a copy operation is admitted at a time, before buffering document bytes; uploads share their buffer with Graph chunks rather than duplicating the document. Busy transfers return HTTP 503 and must be retried. Receiving an upload body times out after five minutes so a stalled editor cannot block later saves indefinitely. A connected editor or in-flight transfer keeps its document session alive beyond the idle expiry; disconnected idle sessions still expire.

This precursor uses an eagerly started per-user service to register a dynamic loopback endpoint and retry provisioning while the profile is locked. Socket activation and a stable endpoint lifecycle remain work for #1736. Office/OneDrive trace collection and real-tenant concurrent-save validation have not been completed. A version that preserves recognized message names while changing save semantics cannot be detected by the current protocol. Do not treat this implementation or its mock tests as production compatibility certification.

Site discovery is available only if the broker's delegated token has `Sites.Read.All` or `Sites.ReadWrite.All`; file-only tokens can still browse accessible drives. The SharePoint search link is hidden without that consent. Each broker connection/account/token operation has a 30-second timeout. If Graph rejects a cached bearer with HTTP 401, the bridge reacquires through the broker and retries read-only requests once. Writes and sharing-link redemption are not automatically replayed; retry them explicitly after the authentication failure.

## Recovery and removal

The picker includes **Recovery copies**, which works even when Microsoft 365 is unavailable. It lets the signed-in user download preserved edits and explicitly remove copies after recovery. A failed save atomically replaces the latest recovery copy for that editor session, preserving the earlier copy if writing fails. Storage is limited to 32 copies and 1 GB, with up to one extra document's temporary bytes during replacement. At the limit the bridge refuses another copy and warns the user to keep the document open and export it locally; it never discards a different document to make room. Successful save retries remove superseded recovery copies for that session. Failed saves return the recovery path; failed preservation returns a distinct insufficient-storage error.

Unsaved copies survive service restart and logout so a failed upload is not silently lost. This intentionally differs from the original logout-cleanup criterion; bounded user-managed retention is the policy for this experimental precursor. New copies include a private source-identity sidecar, so the picker and downloads retain the original filename after restart. Older copies without metadata still work, but need their original document filename extension restored after download.

Upload URLs are bound to the document revision at issuance. A delayed or retried URL is rejected before reading its body if another save has succeeded, rather than inheriting the newer save’s eTag.

Only one bridge process may own a state directory. Before writing another recovery copy, it reclaims recognized temporary files left by a crashed write. Cleanup refuses to run while that bridge is active. A private, empty sibling `himmelblau-collabora.lock` file remains after cleanup so concurrent processes always coordinate through the same lock file.

DEB/RPM package removal stops active bridges before running `himmelblau-collabora cleanup` as each applicable profile owner, including logged-out users. If a bridge cannot be stopped or its status is uncertain, removal aborts before any profile cleanup. Cleanup removes only the Himmelblau provider from the provider list, then removes endpoint, diagnostic, and recovery state. Export recovery copies and close Collabora before uninstalling. A locked profile aborts cleanup with a retry instruction rather than claiming success. For custom XDG configuration/state directories, run the cleanup command in that user's session with those environment variables set before uninstalling. Registration is restricted to existing profiles; newly created and existing profile roots/localStorage directories are restricted to 0700, and existing database files to 0600.

## Arch, Gentoo, and NixOS packaging

The bridge remains optional on these platforms:

- `make arch` produces both the core `himmelblau` package and a separate `himmelblau-collabora` package. `make install` installs only the Arch core package. To opt in, install both matching packages with `sudo pacman -U ./packaging/himmelblau-[0-9]*.pkg.tar.zst ./packaging/himmelblau-collabora-*.pkg.tar.zst`; use the same command to upgrade them together.
- `make gentoo` generates an ebuild with a default-off `collabora` USE flag. Enable that flag when emerging the generated ebuild to install the bridge and its desktop integration.
- Nix exposes `packages.<system>.collabora` (or `packages.collabora` when importing `default.nix` directly). Build it with `nix build .#collabora`. With the Himmelblau NixOS module enabled, add the package to both `environment.systemPackages` and `systemd.packages`:

  ```nix
  let
    collabora = himmelblau.packages.${pkgs.stdenv.hostPlatform.system}.collabora;
  in {
    environment.systemPackages = [ collabora ];
    systemd.packages = [ collabora ];
    # Preserve open document sessions across configuration switches.
    systemd.user.services.himmelblau-collabora.restartIfChanged = false;
  }
  ```

These packages install the executable, user unit, and XDG autostart entry. They do not run the DEB/RPM maintainer scripts. The bridge starts at the next login to a desktop session supporting XDG autostart; to start it in an existing session, run `systemctl --user daemon-reload && systemctl --user start himmelblau-collabora.service`. Install Collabora separately, and retain the identity broker supplied by the Arch core package, Gentoo USE flag, or NixOS module.

Before removing the Arch package, disabling the Gentoo USE flag, or removing the Nix package/configuration, export recovery copies and close Collabora. Then, in each affected user's session, run `systemctl --user stop himmelblau-collabora.service && himmelblau-collabora cleanup`. Only proceed with removal after cleanup succeeds. This also preserves any custom XDG paths from that user's environment.

On Arch, `make uninstall` additionally runs the repository's stop-and-cleanup helper for all discovered profile owners before invoking pacman. Account lookup, service shutdown, or profile cleanup failure prevents package removal. Direct pacman removal has no such hook, so the per-user cleanup above is required. On DEB/RPM systems, `make uninstall` includes the bridge when installed so its package removal hook runs.

See [MANUAL_TESTING.md](MANUAL_TESTING.md) for the automated fixtures and remaining release gates.
