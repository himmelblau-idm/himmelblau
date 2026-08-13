/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2026

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

//! Dispatch tests for o365-url-handler.sh (GHSA-4f5j-9xgm-8pvr).
//!
//! The handler decides whether a URL is loaded in the teams-for-linux Electron
//! window, which exposes Node's require() to page scripts, or handed to the
//! browser. Anything but an allowlisted Microsoft 365 https origin must go to
//! the browser, no matter what the file= query parameter claims.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Which sink the handler dispatched to.
#[derive(Debug, PartialEq, Eq)]
enum Sink {
    /// Loaded in the Electron app, with the selected profile.
    Electron { profile: String, url: String },
    /// Handed to the browser.
    Browser { url: String },
    /// Neither; the handler had nothing to do.
    None,
}

/// A stub PATH plus a rewritten copy of the handler, one per test.
struct Harness {
    dir: PathBuf,
}

impl Harness {
    fn new(tag: &str) -> Harness {
        let dir = std::env::temp_dir().join(format!(
            "o365-url-handler-test-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create harness dir");

        let log = dir.join("calls.log");
        write_stub(&dir.join("o365-multi"), "electron", &log);
        write_stub(&dir.join("xdg-open"), "browser", &log);

        // Point the handler at the stub launcher. This is the same
        // /usr/bin/o365 -> launcher rewrite default.nix performs.
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/o365-url-handler.sh");
        let script = fs::read_to_string(&src).expect("read o365-url-handler.sh");
        let script = script.replace(
            "/usr/bin/o365-multi",
            dir.join("o365-multi").to_str().unwrap(),
        );
        let handler = dir.join("o365-url-handler");
        fs::write(&handler, script).expect("write handler copy");
        make_executable(&handler);

        Harness { dir }
    }

    fn run(&self, args: &[&str]) -> Sink {
        let log = self.dir.join("calls.log");
        let _ = fs::remove_file(&log);

        let out = Command::new("bash")
            .arg(self.dir.join("o365-url-handler"))
            .args(args)
            // The stubs shadow anything of the same name on the real PATH.
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.dir.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .output()
            .expect("run handler");
        assert!(
            out.status.success(),
            "handler failed for {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );

        let Ok(record) = fs::read_to_string(&log) else {
            return Sink::None;
        };
        let mut lines = record.lines();
        let sink = lines.next().expect("sink name").to_string();
        let argv: Vec<&str> = lines.collect();

        match sink.as_str() {
            "browser" => Sink::Browser {
                url: argv.first().expect("xdg-open url").to_string(),
            },
            "electron" => Sink::Electron {
                profile: flag(&argv, "--profile=").expect("--profile"),
                url: flag(&argv, "--url=").expect("--url"),
            },
            other => panic!("unknown sink {other}"),
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn flag(argv: &[&str], prefix: &str) -> Option<String> {
    argv.iter()
        .find(|a| a.starts_with(prefix))
        .map(|a| a[prefix.len()..].to_string())
}

/// A stub that records its name and argv, one per line, then exits 0.
fn write_stub(path: &Path, name: &str, log: &Path) {
    fs::write(
        path,
        format!(
            "#!/usr/bin/env bash\n\
             {{ printf '%s\\n' {name}; printf '%s\\n' \"$@\"; }} > '{log}'\n",
            name = name,
            log = log.display(),
        ),
    )
    .expect("write stub");
    make_executable(path);
}

fn make_executable(path: &Path) {
    let mut perms = fs::metadata(path).expect("stat").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("chmod");
}

/// Real Microsoft 365 document links keep working.
#[test]
fn allowlisted_origins_open_in_electron() {
    let h = Harness::new("allowed");

    let cases = [
        // Tenant SharePoint, which is where file= actually comes from.
        (
            "https://contoso.sharepoint.com/:w:/r/sites/X/_layouts/15/Doc.aspx?sourcedoc=%7Bab%7D&file=Report.docx&action=default",
            "Word",
        ),
        // OneDrive for Business.
        (
            "https://contoso-my.sharepoint.com/personal/u/_layouts/15/Doc.aspx?file=Budget.xlsx",
            "Excel",
        ),
        // Office Online rendering hosts.
        (
            "https://word-edit.officeapps.live.com/we/wordeditorframe.aspx?file=Deck.pptx",
            "PowerPoint",
        ),
        // Exact-match hosts.
        ("https://word.cloud.microsoft/?file=r.docx", "Word"),
        ("https://outlook.office.com/mail/?file=r.docx", "Word"),
        ("https://www.office.com/launch?file=r.xlsx", "Excel"),
        // Host comparison and extension lookup are both case folded.
        ("https://WORD.CLOUD.MICROSOFT/?file=R.DOCX", "Word"),
        // An explicit :443 is still the https origin.
        ("https://word.cloud.microsoft:443/?file=r.docx", "Word"),
    ];

    for (url, want_profile) in cases {
        assert_eq!(
            h.run(&[url]),
            Sink::Electron {
                profile: want_profile.to_string(),
                url: url.to_string(),
            },
            "expected {url} to open in the {want_profile} profile"
        );
    }
}

/// The advisory PoC and its near misses must never reach the Electron app.
#[test]
fn untrusted_origins_go_to_the_browser() {
    let h = Harness::new("denied");

    let cases = [
        // GHSA-4f5j-9xgm-8pvr: file= is not evidence of trust.
        "https://attacker.example/poc.html?file=report.docx",
        // Plaintext, even for an allowlisted host.
        "http://contoso.sharepoint.com/_layouts/15/Doc.aspx?file=r.docx",
        // Userinfo pointing the real authority elsewhere.
        "https://word.cloud.microsoft@attacker.example/?file=r.docx",
        // Backslash: browsers normalize it to '/', which moves the authority
        // boundary. Rejected rather than reinterpreted.
        "https://word.cloud.microsoft\\@attacker.example/?file=r.docx",
        "https://word.cloud.microsoft\\.attacker.example/?file=r.docx",
        // Allowlisted name as a prefix of an attacker-registered domain.
        "https://contoso.sharepoint.com.attacker.tld/?file=r.docx",
        // No label boundary before the parent domain.
        "https://evilsharepoint.com/?file=r.docx",
        // Nested labels under a tenant parent domain.
        "https://a.b.sharepoint.com/?file=r.docx",
        // The bare parent domain has no tenant label.
        "https://sharepoint.com/?file=r.docx",
        // A non-443 port is a different origin.
        "https://word.cloud.microsoft:8443/?file=r.docx",
        // Percent-encoded host.
        "https://%77ord.cloud.microsoft/?file=r.docx",
        // Trailing-dot and case tricks around a non-allowlisted host.
        "https://attacker.example./?file=r.docx",
    ];

    for url in cases {
        assert_eq!(
            h.run(&[url]),
            Sink::Browser {
                url: url.to_string(),
            },
            "expected {url} to be handed to the browser"
        );
    }
}

/// An allowlisted origin with no Office extension still goes to the browser,
/// and an invocation with no URL does nothing at all.
#[test]
fn non_office_links_and_empty_invocations() {
    let h = Harness::new("fallback");

    for url in [
        "https://contoso.sharepoint.com/sites/X/Shared%20Documents/notes.txt?file=notes.txt",
        "https://m365.cloud.microsoft/launch/OneNote/",
    ] {
        assert_eq!(
            h.run(&[url]),
            Sink::Browser {
                url: url.to_string(),
            },
            "expected {url} to be handed to the browser"
        );
    }

    assert_eq!(h.run(&[]), Sink::None);
    assert_eq!(h.run(&["mailto:user@example.com"]), Sink::None);
}
