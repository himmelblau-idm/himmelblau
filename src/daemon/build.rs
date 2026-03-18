use std::env;
use std::io::ErrorKind;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    // src/daemon -> repo root
    let project_root = Path::new(&manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let script_path = project_root.join("src/common/scripts/gen_param_code.py");
    let xml_dir = project_root.join("src/common/docs-xml/himmelblauconf");
    let target_dir = target_dir(&project_root);
    let conf_output = target_dir.join("config/himmelblau.conf.example");
    let debian_conf_output = target_dir.join("debian/himmelblau.conf.example");

    println!("cargo:rerun-if-changed={}", script_path.display());
    println!("cargo:rerun-if-changed={}", xml_dir.display());
    for entry in walkdir(&xml_dir) {
        println!("cargo:rerun-if-changed={}", entry.display());
    }

    let status = Command::new("python3")
        .arg(&script_path)
        .arg("--gen-conf-example")
        .arg("--conf-example-output")
        .arg(&conf_output)
        .arg("--gen-debian-conf-example")
        .arg("--debian-conf-example-output")
        .arg(&debian_conf_output)
        .arg("--xml-dir")
        .arg(&xml_dir)
        .status();

    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            panic!("gen_param_code.py failed with exit code: {:?}", s.code());
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            println!(
                "cargo:warning=python3 not found; skipping himmelblau.conf.example generation"
            );
        }
        Err(e) => {
            panic!(
                "Failed to run gen_param_code.py: {}. Make sure python3 is installed.",
                e
            );
        }
    }
}

fn target_dir(project_root: &Path) -> PathBuf {
    match env::var_os("CARGO_TARGET_DIR") {
        Some(path) => {
            let path = PathBuf::from(path);
            if path.is_absolute() {
                path
            } else {
                project_root.join(path)
            }
        }
        None => project_root.join("target"),
    }
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
