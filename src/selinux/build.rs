// build.rs
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn main() {
    // Inputs
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let te_path = manifest_dir.join("src").join("himmelblaud.te");

    // Outputs
    let out_dir = manifest_dir.join("target").join("selinux");
    let gen_dir = out_dir.join("gen");
    let mod_path = out_dir.join("himmelblaud.mod");
    let fc_path = out_dir.join("himmelblaud.fc"); // merged FC we’ll generate
    let pp_path = out_dir.join("himmelblaud.pp");

    // Rebuild triggers
    println!("cargo:rerun-if-changed={}", te_path.display());
    println!("cargo:rerun-if-env-changed=HIMMELBLAU_ALLOW_MISSING_SELINUX");

    // Sanity
    if !te_path.exists() {
        eprintln!("error: missing {}", te_path.display());
        std::process::exit(1);
    }

    // Toolchain checks
    let have_checkmodule = which("checkmodule");
    let have_semodule_package = which("semodule_package");
    let have_sepolicy = which("sepolicy");

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

    // Prepare dirs
    fs::create_dir_all(&out_dir).expect("create target/selinux");
    fs::create_dir_all(&gen_dir).expect("create target/selinux/gen");

    // Scaffold FC using sepolicy generate for each system daemon
    let daemon_bins: &[(&str, &str)] = &[
        ("/usr/sbin/himmelblaud", "himmelblaud"),
        ("/usr/sbin/himmelblaud_tasks", "himmelblaud_tasks"),
    ];

    let mut merged_fc_lines: BTreeSet<String> = BTreeSet::new();

    if have_sepolicy {
        for (path, name) in daemon_bins {
            let this_gen = gen_dir.join(name);
            fs::create_dir_all(&this_gen).expect("create per-daemon gen dir");

            // Run: sepolicy generate --init <path>    (outputs *in CWD*)
            run_in_dir(
                &this_gen,
                "sepolicy",
                &["generate", "--init", path],
            );

            // Pull in its .fc (if present)
            let fc_guess = this_gen.join(format!("{name}.fc"));
            if fc_guess.exists() {
                merge_fc(&fc_guess, &mut merged_fc_lines);
            } else {
                println!("cargo:warning=sepolicy did not produce {}.fc; skipping", name);
            }
        }
    } else {
        println!("cargo:warning=sepolicy not found; skipping FC scaffolding.");
    }

    // Write merged .fc
    let mut fc_out = fs::File::create(&fc_path).expect("create merged fc");
    for line in &merged_fc_lines {
        writeln!(fc_out, "{line}").unwrap();
    }

    // Build module from your TE + merged FC
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

    run(
        "semodule_package",
        &[
            "-o",
            &pp_path.to_string_lossy(),
            "-m",
            &mod_path.to_string_lossy(),
            "-f",
            &fc_path.to_string_lossy(),
        ],
    );

    println!("cargo:warning=Built SELinux policy: {}", pp_path.display());
    println!("cargo:warning=Also wrote merged FC: {}", fc_path.display());
    println!("cargo:warning=Scaffold files (for reference) in: {}", gen_dir.display());
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
    let status = Command::new(cmd).args(args).status()
        .unwrap_or_else(|e| panic!("failed to exec {}: {}", cmd, e));
    if !status.success() {
        panic!("command failed: {} {}", cmd, args.join(" "));
    }
}

fn run_in_dir(cwd: &Path, cmd: &str, args: &[&str]) {
    let status = Command::new(cmd).current_dir(cwd).args(args).status()
        .unwrap_or_else(|e| panic!("failed to exec {} in {}: {}", cmd, cwd.display(), e));
    if !status.success() {
        panic!("command failed in {}: {} {}", cwd.display(), cmd, args.join(" "));
    }
}

fn merge_fc(fc_file: &Path, acc: &mut BTreeSet<String>) {
    let mut s = String::new();
    fs::File::open(fc_file)
        .and_then(|mut f| f.read_to_string(&mut s))
        .expect("read .fc");
    for line in s.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') { continue; }
        acc.insert(l.to_string());
    }
}

fn shell_escape(s: &str) -> String {
    s.replace('"', "\\\"").replace('\'', "\\'")
}
