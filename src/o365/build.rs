/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2025

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
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Where to install desktop files will point.
const DEFAULT_EXEC: &str = "/usr/bin/o365"; // override with env O365_EXEC
/// Where to write generated assets (relative to repo root).
const GEN_SUBDIR: &str = "generated";

#[derive(Clone)]
struct App {
    name: &'static str,
    slug: &'static str,
    url: &'static str,
    categories: &'static str,
    /// Icon key inside the icon repo (we try this first, then fallbacks)
    icon_key: &'static str,
}

fn apps() -> Vec<App> {
    vec![
        App {
            name: "Apps",
            slug: "apps",
            url: "https://m365.cloud.microsoft/apps",
            categories: "Office;",
            icon_key: "apps",
        },
        App {
            name: "Outlook",
            slug: "outlook",
            url: "https://outlook.office.com/mail/",
            categories: "Office;Calendar;Contacts;Email;Network;",
            icon_key: "outlook",
        },
        App {
            name: "Teams",
            slug: "teams",
            url: "https://teams.microsoft.com/",
            categories: "Office;Utility;",
            icon_key: "teams",
        },
        App {
            name: "Word",
            slug: "word",
            url: "https://word.cloud.microsoft/",
            categories: "Office;WordProcessor;",
            icon_key: "word",
        },
        App {
            name: "Excel",
            slug: "excel",
            url: "https://excel.cloud.microsoft/",
            categories: "Office;Spreadsheet;",
            icon_key: "excel",
        },
        App {
            name: "PowerPoint",
            slug: "powerpoint",
            url: "https://powerpoint.cloud.microsoft/",
            categories: "Office;Presentation;",
            icon_key: "powerpoint",
        },
        App {
            name: "OneNote",
            slug: "onenote",
            url: "https://m365.cloud.microsoft/launch/OneNote/",
            categories: "Office;Utility;",
            icon_key: "onenote",
        },
        App {
            name: "OneDrive",
            slug: "onedrive",
            url: "https://www.office.com/onedrive",
            categories: "Office;FileTransfer;Network;",
            icon_key: "onedrive",
        },
        App {
            name: "SharePoint",
            slug: "sharepoint",
            url: "https://www.office.com/launch/sharepoint",
            categories: "Office;Network;",
            icon_key: "sharepoint",
        },
    ]
}

fn main() {
    // Rebuild triggers
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=O365_EXEC");
    println!("cargo:rerun-if-env-changed=O365_FETCH_ICONS");
    println!("cargo:rerun-if-env-changed=O365_OFFLINE");
    println!("cargo:rerun-if-env-changed=O365_GEN_DIR");

    let exec = env::var("O365_EXEC").unwrap_or_else(|_| DEFAULT_EXEC.to_string());
    let offline = env::var("O365_OFFLINE").ok().as_deref() == Some("1");
    let fetch_icons = env::var("O365_FETCH_ICONS").ok().as_deref() != Some("0"); // default ON
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let gen_root = env::var("O365_GEN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest.join(GEN_SUBDIR));

    fs::create_dir_all(&gen_root).expect("mkdir -p generated");

    // Attribution file for icon source/license.
    let mut notice = File::create(gen_root.join("NOTICE.txt")).unwrap();
    writeln!(
        notice,
        "Office 365 icons fetched from https://github.com/sempostma/office365-icons (MIT license).\n\
         Icons are 256x256 PNG where available; some apps may fall back to a generic icon."
    ).unwrap();

    // Always ensure we have at least one fallback icon present (try teams, then outlook).
    let fallback_keys = &["teams", "outlook"];
    let fallback_icon_path = if fetch_icons && !offline {
        fallback_keys
            .iter()
            .find_map(|k| fetch_icon_into(&gen_root, "o365-fallback", k).ok())
    } else {
        None
    };

    for app in apps() {
        // 1) Icon: try requested key; if missing, fall back to office → teams → outlook → last resort shared fallback.
        let icon_basename = format!("o365-{}.png", app.slug);
        let icon_path = gen_root.join(&icon_basename);

        if fetch_icons && !offline {
            if let Err(e) = fetch_icon_into(&gen_root, &format!("o365-{}", app.slug), app.icon_key)
            {
                println!(
                    "cargo:warning=icon '{}' not found ({:?}); trying fallbacks for '{}'",
                    app.icon_key, e, app.slug
                );

                let fallback_chain = ["office", "teams", "outlook"];
                let mut ok = false;
                for key in fallback_chain {
                    if fetch_icon_into(&gen_root, &format!("o365-{}", app.slug), key).is_ok() {
                        ok = true;
                        break;
                    }
                }
                if !ok {
                    // Copy the pre-fetched shared fallback if we have it
                    if let Some(fp) = &fallback_icon_path {
                        let _ = fs::copy(fp, &icon_path);
                    }
                }
            }
        }

        // 2) .desktop
        let desktop_path = gen_root.join(format!("o365-{}.desktop", app.slug));
        write_desktop(&desktop_path, &app, &exec);
    }

    // Small note to help packaging
    println!(
        "cargo:warning=Generated desktop files in: {}",
        gen_root.display()
    );
    println!("cargo:warning=Generated icons in: {}", gen_root.display());
}

/// Download `<key>.png` (256px) from the icon repo into `gen_root` under `<basename>.png`.
fn fetch_icon_into(gen_root: &Path, basename_no_ext: &str, key: &str) -> anyhow::Result<PathBuf> {
    let dest = gen_root.join(format!("{}.png", basename_no_ext));
    if dest.exists() {
        return Ok(dest);
    }

    if key == "apps" {
        fs::copy("src/o365-apps.png", &dest)?;
        return Ok(dest);
    }

    let url = format!(
        "https://github.com/sempostma/office365-icons/raw/master/png/256/{}.png",
        key
    );
    let bytes = http_get(&url)?;
    fs::write(&dest, bytes)?;
    Ok(dest)
}

fn http_get(url: &str) -> anyhow::Result<Vec<u8>> {
    // Build-dep: reqwest (blocking, rustls)
    let client = reqwest::blocking::Client::builder()
        .user_agent("o365-desktop-gen/1.0")
        .build()?;
    let resp = client.get(url).send()?;
    if !resp.status().is_success() {
        anyhow::bail!("GET {} -> {}", url, resp.status());
    }
    Ok(resp.bytes()?.to_vec())
}

fn write_desktop(path: &Path, app: &App, exec_path: &str) {
    let mut f = File::create(path).expect("write .desktop");
    // Icon= must be the basename without extension (theme lookup). We install as o365-<slug>.png.
    let icon_name = format!("o365-{}", app.slug);
    let content = format!(
        r#"[Desktop Entry]
Name=Microsoft {name}
Comment=Open Microsoft 365 {name}
Exec={exec} --url={url} --profile={name} --appIcon=/usr/share/icons/hicolor/256x256/apps/{icon}.png --appTitle={name} %U
Terminal=false
Type=Application
Categories={cats}
StartupNotify=true
Icon={icon}
"#,
        name = app.name,
        exec = shell_escape(exec_path),
        url = app.url,
        cats = app.categories,
        icon = icon_name,
    );
    f.write_all(content.as_bytes()).unwrap();
}

fn shell_escape(s: &str) -> String {
    // Minimal quoting for paths with spaces.
    if s.contains(' ') {
        format!("\"{}\"", s)
    } else {
        s.to_string()
    }
}
