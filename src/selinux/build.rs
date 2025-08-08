// build.rs
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() {
    // Where your sources live (relative to Cargo.toml)
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let te_path = manifest_dir.join("src").join("himmelblaud.te");

    // Where we’ll put the compiled .pp for packaging
    // (stable path that both cargo-deb and generate-rpm can reference)
    let out_dir = manifest_dir.join("target").join("selinux");
    let mod_path = out_dir.join("himmelblaud.mod");
    let pp_path = out_dir.join("himmelblaud.pp");

    // Rebuild if inputs change
    println!("cargo:rerun-if-changed={}", te_path.display());
    println!("cargo:rerun-if-env-changed=HIMMELBLAU_ALLOW_MISSING_SELINUX");

    // Make sure sources exist
    if !te_path.exists() {
        eprintln!("error: missing {}", te_path.display());
        std::process::exit(1);
    }

    // Ensure toolchain is present
    let have_checkmodule = which("checkmodule");
    let have_semodule_package = which("semodule_package");

    let allow_missing = env::var_os("HIMMELBLAU_ALLOW_MISSING_SELINUX").is_some();
    if !(have_checkmodule && have_semodule_package) {
        let msg = "SELinux tools (checkmodule, semodule_package) not found. \
                   Install 'checkpolicy' (and policycoreutils) or set \
                   HIMMELBLAU_ALLOW_MISSING_SELINUX=1 to skip (NOT recommended for packaging).";
        if allow_missing {
            println!("cargo:warning={}", msg);
            return;
        } else {
            eprintln!("error: {}", msg);
            std::process::exit(1);
        }
    }

    // Create output dir
    fs::create_dir_all(&out_dir).expect("create target/selinux");

    // Run: checkmodule -M -m -o target/selinux/himmelblaud.mod selinux/himmelblaud.te
    run(
        "checkmodule",
        &[
            "-M",
            "-m",
            "-o",
            &mod_path.to_string_lossy(),
            &te_path.to_string_lossy(),
        ],
    );

    // Run: semodule_package -o target/selinux/himmelblaud.pp -m target/selinux/himmelblaud.mod [-f selinux/himmelblaud.fc]
    let pp_binding = pp_path.to_string_lossy();
    let mod_binding = mod_path.to_string_lossy();
    let args = vec!["-o", &pp_binding, "-m", &mod_binding];
    run("semodule_package", &args);

    println!("cargo:warning=Built SELinux policy: {}", pp_path.display());
}

fn which(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {}", shell_escape(bin)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run(cmd: &str, args: &[&str]) {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to exec {}: {}", cmd, e));
    if !status.success() {
        panic!("command failed: {} {}", cmd, args.join(" "));
    }
}

fn shell_escape(s: &str) -> String {
    // minimal escaping for `command -v`
    s.replace('"', "\\\"").replace('\'', "\\'")
}
