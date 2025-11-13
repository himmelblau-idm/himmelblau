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
    multi: bool,
    url_handler: bool,
}

fn apps() -> Vec<App> {
    vec![
        App {
            name: "Outlook",
            slug: "outlook",
            url: "https://outlook.office.com/mail/",
            categories: "Office;Calendar;Contacts;Email;Network;",
            multi: false,
            url_handler: true,
        },
        App {
            name: "Teams",
            slug: "teams",
            url: "https://teams.microsoft.com/",
            categories: "Office;Utility;",
            multi: false,
            url_handler: true,
        },
        App {
            name: "Word",
            slug: "word",
            url: "https://word.cloud.microsoft/",
            categories: "Office;WordProcessor;",
            multi: true,
            url_handler: false,
        },
        App {
            name: "Excel",
            slug: "excel",
            url: "https://excel.cloud.microsoft/",
            categories: "Office;Spreadsheet;",
            multi: true,
            url_handler: false,
        },
        App {
            name: "PowerPoint",
            slug: "powerpoint",
            url: "https://powerpoint.cloud.microsoft/",
            categories: "Office;Presentation;",
            multi: true,
            url_handler: false,
        },
        App {
            name: "OneNote",
            slug: "onenote",
            url: "https://m365.cloud.microsoft/launch/OneNote/",
            categories: "Office;Utility;",
            multi: true,
            url_handler: false,
        },
        App {
            name: "OneDrive",
            slug: "onedrive",
            url: "https://www.office.com/onedrive",
            categories: "Office;FileTransfer;Network;",
            multi: true,
            url_handler: true,
        },
        App {
            name: "SharePoint",
            slug: "sharepoint",
            url: "https://www.office.com/launch/sharepoint",
            categories: "Office;Network;",
            multi: true,
            url_handler: false,
        },
    ]
}

fn main() {
    // Use a fake file marker to force these to ALWAYS rebuild
    println!("cargo:rerun-if-changed=always_rebuild_marker");

    let exec = env::var("O365_EXEC").unwrap_or_else(|_| DEFAULT_EXEC.to_string());
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let gen_root = env::var("O365_GEN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest.join(GEN_SUBDIR));

    fs::create_dir_all(&gen_root).expect("mkdir -p generated");

    for app in apps() {
        // .desktop
        let desktop_path = gen_root.join(format!("o365-{}.desktop", app.slug));
        write_desktop(&desktop_path, &app, &exec);
    }

    // Small note to help packaging
    println!(
        "cargo:warning=Generated desktop files in: {}",
        gen_root.display()
    );
}

fn write_desktop(path: &Path, app: &App, exec_path: &str) {
    let mut f = File::create(path).expect("write .desktop");
    // Icon= must be the basename without extension (theme lookup). We install as o365-<slug>.png.
    let icon_name = format!("o365-{}", app.slug);
    let tray_icon = !app.multi;
    let x_close = app.multi;
    let multi = if app.multi { "-multi" } else { "" };
    let url_handler = if app.url_handler {
        "--defaultURLHandler /usr/bin/o365-url-handler"
    } else {
        ""
    };
    let content = format!(
        r#"[Desktop Entry]
Name=Microsoft {name}
Comment=Open Microsoft 365 {name}
Exec={exec}{multi} --url={url} --profile={name} --appIcon=/usr/share/icons/hicolor/256x256/apps/{icon}.png --appTitle={name} --closeAppOnCross={x_close} --trayIconEnabled={tray_icon} {url_handler} %U
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
        x_close = x_close,
        tray_icon = tray_icon,
        multi = multi,
        url_handler = url_handler,
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
