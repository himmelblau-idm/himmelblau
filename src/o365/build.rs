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

/// Where to write generated assets (relative to repo root).
const GEN_SUBDIR: &str = "generated";
/// Browser launcher script path
const LAUNCHER: &str = "/usr/bin/o365-browser-launcher";

#[derive(Clone)]
struct App {
    name: &'static str,
    slug: &'static str,
    url: &'static str,
    categories: &'static str,
    mime_types: &'static str, // MIME types this app handles (empty for most)
}

fn apps() -> Vec<App> {
    vec![
        App {
            name: "Outlook",
            slug: "outlook",
            url: "https://outlook.office.com/mail/",
            categories: "Office;Calendar;Contacts;Email;Network;",
            mime_types: "x-scheme-handler/mailto;",
        },
        App {
            name: "Teams",
            slug: "teams",
            url: "https://teams.microsoft.com/",
            categories: "Office;Utility;",
            mime_types: "",
        },
        App {
            name: "Word",
            slug: "word",
            url: "https://word.cloud.microsoft/",
            categories: "Office;WordProcessor;",
            mime_types: "",
        },
        App {
            name: "Excel",
            slug: "excel",
            url: "https://excel.cloud.microsoft/",
            categories: "Office;Spreadsheet;",
            mime_types: "",
        },
        App {
            name: "PowerPoint",
            slug: "powerpoint",
            url: "https://powerpoint.cloud.microsoft/",
            categories: "Office;Presentation;",
            mime_types: "",
        },
        App {
            name: "OneNote",
            slug: "onenote",
            url: "https://m365.cloud.microsoft/launch/OneNote/",
            categories: "Office;Utility;",
            mime_types: "",
        },
        App {
            name: "OneDrive",
            slug: "onedrive",
            url: "https://www.office.com/onedrive",
            categories: "Office;FileTransfer;Network;",
            mime_types: "",
        },
        App {
            name: "SharePoint",
            slug: "sharepoint",
            url: "https://www.office.com/launch/sharepoint",
            categories: "Office;Network;",
            mime_types: "",
        },
    ]
}

fn main() {
    // Use a fake file marker to force these to ALWAYS rebuild
    println!("cargo:rerun-if-changed=always_rebuild_marker");

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let gen_root = env::var("O365_GEN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest.join(GEN_SUBDIR));

    fs::create_dir_all(&gen_root).expect("mkdir -p generated");

    for app in apps() {
        // .desktop
        let desktop_path = gen_root.join(format!("o365-{}.desktop", app.slug));
        write_desktop(&desktop_path, &app);
    }

    // Small note to help packaging
    println!(
        "cargo:warning=Generated desktop files in: {}",
        gen_root.display()
    );
}

fn write_desktop(path: &Path, app: &App) {
    let mut f = File::create(path).expect("write .desktop");
    // Icon= must be the basename without extension (theme lookup). We install as o365-<slug>.png.
    let icon_name = format!("o365-{}", app.slug);

    // Build MimeType line if app handles MIME types
    let mime_line = if !app.mime_types.is_empty() {
        format!("MimeType={}\n", app.mime_types)
    } else {
        String::new()
    };

    let content = format!(
        r#"[Desktop Entry]
Name=Microsoft {name}
Comment=Open Microsoft 365 {name}
Exec={launcher} {url} %U
Terminal=false
Type=Application
Categories={cats}
StartupNotify=true
Icon={icon}
{mime}
"#,
        name = app.name,
        launcher = LAUNCHER,
        url = app.url,
        cats = app.categories,
        icon = icon_name,
        mime = mime_line.trim_end(),
    );
    f.write_all(content.as_bytes()).unwrap();
}
