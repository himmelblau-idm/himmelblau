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

//! Architecture selection tests for the teams-for-linux AppImage wrapper.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

struct Harness {
    dir: PathBuf,
    cache: PathBuf,
}

impl Harness {
    fn new(tag: &str) -> Harness {
        let dir = std::env::temp_dir().join(format!(
            "o365-wrapper-arch-test-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("home")).expect("create home");
        let cache = dir.join("cache");
        fs::create_dir_all(&cache).expect("create cache");

        write_executable(
            &dir.join("uname"),
            "#!/usr/bin/env bash\nprintf '%s\\n' \"${TEST_MACHINE_ARCH:?}\"\n",
        );

        let curl = r#"#!/usr/bin/env bash
set -eu
out=""
url=""
is_head=false
while (( $# )); do
  case "$1" in
    --head) is_head=true ;;
    -o) shift; out="$1" ;;
    http*) url="$1" ;;
  esac
  shift
done
if $is_head; then
  printf 'HEAD %s\n' "$url" >> '@CALLS@'
elif [[ -n "$out" ]]; then
  printf 'DOWNLOAD %s\n' "$url" >> '@CALLS@'
  printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$@" > "$APP_LOG"' > "$out"
else
  printf 'GET %s\n' "$url" >> '@CALLS@'
  printf 'version: 2.6.19\n'
fi
"#
        .replace("@CALLS@", &dir.join("calls.log").display().to_string());
        write_executable(&dir.join("curl"), &curl);

        Harness { dir, cache }
    }

    fn install_cached(&self, asset: &str) {
        let target = self.cache.join(asset);
        write_executable(
            &target,
            "#!/usr/bin/env bash\nprintf '%s\\n' \"$@\" > \"$APP_LOG\"\n",
        );
        symlink(&target, self.cache.join("Teams-for-Linux.AppImage"))
            .expect("create cached AppImage symlink");
    }

    fn run(&self, arch: &str) -> String {
        let out = Command::new("bash")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/o365.sh"))
            .env("TEST_MACHINE_ARCH", arch)
            .env("TEAMSL_APP_DIR", &self.cache)
            .env("HOME", self.dir.join("home"))
            .env("CURL_BIN", self.dir.join("curl"))
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
            .expect("run o365 wrapper");
        assert!(
            out.status.success(),
            "wrapper failed on {arch}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        fs::read_to_string(self.dir.join("calls.log")).expect("read curl calls")
    }

    fn linked_asset(&self) -> String {
        fs::read_link(self.cache.join("Teams-for-Linux.AppImage"))
            .expect("read AppImage symlink")
            .file_name()
            .expect("asset filename")
            .to_string_lossy()
            .into_owned()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write executable");
    let mut perms = fs::metadata(path).expect("stat executable").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("chmod executable");
}

#[test]
fn x86_64_uses_unsuffixed_assets() {
    let h = Harness::new("x86");
    let calls = h.run("x86_64");

    assert!(calls.contains("teams-for-linux-2.6.19.AppImage"));
    assert!(calls.contains("latest-linux.yml"));
    assert!(!calls.contains("arm64"));
    assert_eq!(h.linked_asset(), "Teams-for-Linux-2.6.19.AppImage");
}

#[test]
fn arm64_replaces_same_version_x86_64_cache() {
    let h = Harness::new("arm64-migrate");
    h.install_cached("Teams-for-Linux-2.6.19.AppImage");
    let calls = h.run("aarch64");

    assert!(calls.contains("DOWNLOAD https://github.com/IsmaelMartinez/teams-for-linux/releases/download/v2.6.19/teams-for-linux-2.6.19-arm64.AppImage"));
    assert!(calls.contains("GET https://github.com/IsmaelMartinez/teams-for-linux/releases/download/v2.6.19/latest-linux-arm64.yml"));
    assert_eq!(h.linked_asset(), "Teams-for-Linux-2.6.19-arm64.AppImage");
}

#[test]
fn matching_arm64_cache_is_not_downloaded_again() {
    let h = Harness::new("arm64-current");
    h.install_cached("Teams-for-Linux-2.6.19-arm64.AppImage");
    let calls = h.run("arm64");

    assert!(calls.contains("HEAD https://github.com/IsmaelMartinez/teams-for-linux/releases/download/v2.6.19/teams-for-linux-2.6.19-arm64.AppImage"));
    assert!(!calls.contains("DOWNLOAD"));
    assert!(!calls.contains("GET "));
}
