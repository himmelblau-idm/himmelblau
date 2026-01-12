use std::env;
use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");

    // Calculate paths relative to the manifest directory
    let project_root = Path::new(&manifest_dir).parent().unwrap().parent().unwrap();
    let script_path = project_root.join("scripts/gen_param_code.py");
    let xml_dir = project_root.join("docs-xml/himmelblauconf");
    let rust_output = Path::new(&out_dir).join("config_gen.rs");

    // Set up rerun-if-changed for the script and XML files
    println!("cargo:rerun-if-changed={}", script_path.display());

    // Watch all XML files in the parameter directories
    for entry in walkdir(&xml_dir) {
        if entry.extension().map_or(false, |e| e == "xml") {
            println!("cargo:rerun-if-changed={}", entry.display());
        }
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
            panic!(
                "gen_param_code.py failed with exit code: {:?}",
                s.code()
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

/// Simple directory walker that returns all file paths
fn walkdir(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_dir() {
                files.extend(walkdir(&path));
            } else {
                files.push(path);
            }
        }
    }
    files
}
