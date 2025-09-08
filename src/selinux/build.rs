use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn find_target_dir() -> PathBuf {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set by cargo");
    // Find the ancestor named "build", then take its parent => <profile> dir.
    let mut profile_dir: Option<PathBuf> = None;
    let mut target_root: Option<PathBuf> = None;
    for ancestor in Path::new(&out_dir).ancestors() {
        if ancestor.file_name().and_then(|s| s.to_str()) == Some("build") {
            profile_dir = ancestor.parent().map(|p| p.to_path_buf());
        }
        if ancestor.file_name().and_then(|s| s.to_str()) == Some("target") {
            target_root = Some(ancestor.to_path_buf());
            break;
        }
    }
    let profile_dir = profile_dir.expect("Could not locate <profile> dir from OUT_DIR");
    let profile_name = profile_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap()
        .to_string();

    let target_root = target_root.expect("Could not locate target/ root from OUT_DIR");
    // Canonical path without the triple: target/<profile>
    target_root.join(&profile_name)
}

fn main() {
    // Path to your policy sources
    let policy_dir = Path::new("src");
    // Path to target output dir
    let out_dir = find_target_dir();

    // Tell Cargo to rerun if the policy files change
    println!(
        "cargo:rerun-if-changed={}",
        policy_dir.join("himmelblaud.te").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        policy_dir.join("himmelblaud.fc").display()
    );
    println!("cargo:rerun-if-env-changed=HIMMELBLAU_ALLOW_MISSING_SELINUX");

    let allow_missing = env::var_os("HIMMELBLAU_ALLOW_MISSING_SELINUX").is_some();
    if !allow_missing {
        // Run the SELinux build using the system Makefile
        let status = Command::new("make")
            .current_dir(policy_dir)
            .arg("-f")
            .arg("/usr/share/selinux/devel/Makefile")
            .arg("NAME=himmelblaud")
            .status()
            .expect("Failed to invoke SELinux makefile");

        if !status.success() {
            panic!("SELinux policy build failed");
        }

        // Move result into Cargo’s target dir
        let src_pp = policy_dir.join("himmelblaud.pp");
        let dst_pp = Path::new(&out_dir).join("himmelblaud.pp");
        fs::copy(&src_pp, &dst_pp).expect("Failed to copy policy module to OUT_DIR");

        println!("cargo:warning=Built SELinux policy: {}", dst_pp.display());
    } else {
        println!("cargo:warning=SELinux policy build disabled.");
    }
}
