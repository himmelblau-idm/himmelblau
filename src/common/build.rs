use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    // Calculate paths relative to the manifest directory
    let project_root = Path::new(&manifest_dir);
    let workspace_root = project_root.parent().unwrap().parent().unwrap();
    let script_path = project_root.join("scripts/gen_param_code.py");
    let xml_dir = project_root.join("docs-xml/himmelblauconf");
    let rust_output = Path::new(&out_dir).join("config_gen.rs");
    let po_dir = workspace_root.join("po");

    // Set up rerun-if-changed for the script and XML files
    println!("cargo:rerun-if-changed={}", script_path.display());
    println!("cargo:rerun-if-changed={}", po_dir.display());

    // Watch the XML directory itself so new files trigger a rebuild
    println!("cargo:rerun-if-changed={}", xml_dir.display());

    // Watch all XML files and subdirectories in the parameter directories
    for entry in walkdir(&xml_dir) {
        // Watch directories too, so new files in them trigger rebuilds
        println!("cargo:rerun-if-changed={}", entry.display());
    }
    for entry in walkdir(&po_dir) {
        println!("cargo:rerun-if-changed={}", entry.display());
    }

    // Call the Python script to generate Rust code
    let status = Command::new("python3")
        .arg(&script_path)
        .arg("--gen-rust")
        .arg("--rust-output")
        .arg(&rust_output)
        .arg("--xml-dir")
        .arg(&xml_dir)
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:warning=Generated config_gen.rs successfully");
        }
        Ok(s) => {
            panic!("gen_param_code.py failed with exit code: {:?}", s.code());
        }
        Err(e) => {
            panic!(
                "Failed to run gen_param_code.py: {}. Make sure python3 is installed.",
                e
            );
        }
    }

    compile_gettext_catalogs(workspace_root, &po_dir);
}

/// Simple directory walker that returns all file and directory paths
fn walkdir(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                paths.push(path.clone());
                paths.extend(walkdir(&path));
            } else {
                paths.push(path);
            }
        }
    }
    paths
}

fn compile_gettext_catalogs(workspace_root: &Path, po_dir: &Path) {
    let linguas_path = po_dir.join("LINGUAS");
    let linguas = match std::fs::read_to_string(&linguas_path) {
        Ok(contents) => contents,
        Err(_) => return,
    };

    let languages: Vec<String> = linguas
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect();

    if languages.is_empty() {
        return;
    }

    let target_locale_dir = target_profile_dir(workspace_root).join("locale");
    for lang in languages {
        let po_file = po_dir.join(format!("{lang}.po"));
        if !po_file.is_file() {
            panic!(
                "po/LINGUAS lists '{lang}', but {} is missing",
                po_file.display()
            );
        }

        let mo_dir = target_locale_dir.join(&lang).join("LC_MESSAGES");
        if let Err(e) = std::fs::create_dir_all(&mo_dir) {
            panic!("Failed to create {}: {}", mo_dir.display(), e);
        }

        let mo_file = mo_dir.join("himmelblau.mo");
        let status = Command::new("msgfmt")
            .arg("--check-format")
            .arg("--output-file")
            .arg(&mo_file)
            .arg(&po_file)
            .status();

        match status {
            Ok(s) if s.success() => {}
            Ok(s) => panic!(
                "msgfmt failed for {} with exit code {:?}",
                po_file.display(),
                s.code()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                println!(
                    "cargo:warning=msgfmt not found; skipping gettext catalog compilation. Install gettext/msgfmt to build translated catalogs."
                );
                return;
            }
            Err(e) => panic!("Failed to run msgfmt for {}: {}", po_file.display(), e),
        }
    }
}

fn target_profile_dir(workspace_root: &Path) -> PathBuf {
    let target_dir = match env::var_os("CARGO_TARGET_DIR") {
        Some(path) => {
            let path = PathBuf::from(path);
            if path.is_absolute() {
                path
            } else {
                workspace_root.join(path)
            }
        }
        None => workspace_root.join("target"),
    };

    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target = env::var("TARGET").unwrap_or_default();
    let host = env::var("HOST").unwrap_or_default();

    if !target.is_empty() && target != host {
        target_dir.join(target).join(profile)
    } else {
        target_dir.join(profile)
    }
}
