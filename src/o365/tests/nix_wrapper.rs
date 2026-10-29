/*
   Unix Azure Entra ID implementation
   Copyright (C) Nicolas Goudry <goudry.nicolas@gmail.com> 2026

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

//! Argument tests for the Nix teams-for-linux wrapper (nix-o365.sh).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Harness {
    dir: PathBuf,
}

impl Harness {
    fn new(tag: &str) -> Harness {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "o365-nix-wrapper-test-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("home")).expect("create home");

        let stub = dir.join("teams-for-linux");
        fs::write(
            &stub,
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > \"$APP_LOG\"\n",
        )
        .expect("write teams-for-linux stub");
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755))
            .expect("chmod teams-for-linux stub");

        Harness { dir }
    }

    fn run(&self, args: &[&str]) -> Vec<String> {
        let out = Command::new("bash")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/nix-o365.sh"))
            .args(args)
            .env("HOME", self.dir.join("home"))
            .env("APP_LOG", self.dir.join("app.log"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.dir.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .output()
            .expect("run nix o365 wrapper");
        assert!(
            out.status.success(),
            "wrapper failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        fs::read_to_string(self.dir.join("app.log"))
            .expect("read teams-for-linux arguments")
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn enables_intune_sso_with_the_nested_option() {
    let h = Harness::new("intune");
    let profile = h.dir.join("home/.config/o365-profiles/Outlook-2");
    let args = h.run(&[
        "--url=https://outlook.office.com/mail/",
        "--profile=Outlook-2",
    ]);

    assert_eq!(
        args,
        [
            "--auth.intune.enabled=true".to_owned(),
            format!("--user-data-dir={}", profile.display()),
            "--class=o365-Outlook".to_owned(),
            "--url=https://outlook.office.com/mail/".to_owned(),
        ]
    );
    assert!(profile.is_dir());
}
