use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Minimum GNOME Shell version that supports ES modules (ESM)
const GNOME_ESM_MIN_VERSION: u32 = 45;

/// Parse a version string to extract the major version number
fn parse_major_version(version_str: &str) -> Option<u32> {
    // Handle various formats:
    // - "45.1" or "43.9"
    // - "1:45.0-1" (with epoch)
    // - "46.0-1ubuntu1" (with distro suffix)
    let version_str = version_str.trim();

    // Strip epoch prefix (e.g., "1:45.0" -> "45.0")
    let version_str = version_str.split(':').next_back().unwrap_or(version_str);

    // Get major version (first number before '.')
    if let Some(major_str) = version_str.split('.').next() {
        // Also handle cases like "45-1" without minor version
        let major_str = major_str.split('-').next().unwrap_or(major_str);
        return major_str.parse::<u32>().ok();
    }

    None
}

/// Detect GNOME version from the running gnome-shell binary
fn detect_from_gnome_shell() -> Option<u32> {
    let output = Command::new("gnome-shell").arg("--version").output().ok()?;

    if output.status.success() {
        let version_str = String::from_utf8_lossy(&output.stdout);
        // Output format: "GNOME Shell 45.1"
        if let Some(version_part) = version_str.split_whitespace().last() {
            return parse_major_version(version_part);
        }
    }
    None
}

/// Detect GNOME version from installed RPM package
fn detect_from_rpm_installed() -> Option<u32> {
    let output = Command::new("rpm")
        .args(["-q", "--queryformat", "%{VERSION}", "gnome-shell"])
        .output()
        .ok()?;

    if output.status.success() {
        let version_str = String::from_utf8_lossy(&output.stdout);
        // Check it's not an error message (package not installed returns non-zero anyway)
        if !version_str.contains("not installed") {
            return parse_major_version(&version_str);
        }
    }
    None
}

/// Detect GNOME version from installed DEB package
fn detect_from_dpkg_installed() -> Option<u32> {
    let output = Command::new("dpkg-query")
        .args(["-W", "-f=${Version}", "gnome-shell"])
        .output()
        .ok()?;

    if output.status.success() {
        let version_str = String::from_utf8_lossy(&output.stdout);
        if !version_str.is_empty() {
            return parse_major_version(&version_str);
        }
    }
    None
}

/// Detect GNOME version from DNF repository (Fedora, Rocky, RHEL)
fn detect_from_dnf_repo() -> Option<u32> {
    // Try dnf repoquery first
    let output = Command::new("dnf")
        .args(["repoquery", "--qf", "%{VERSION}", "gnome-shell"])
        .output()
        .ok()?;

    if output.status.success() {
        let version_str = String::from_utf8_lossy(&output.stdout);
        // dnf repoquery might return multiple versions, take the first line
        for line in version_str.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with("Last metadata") {
                if let Some(v) = parse_major_version(line) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Detect GNOME version from Zypper repository (openSUSE, SLE)
fn detect_from_zypper_repo() -> Option<u32> {
    let output = Command::new("zypper")
        .args(["--non-interactive", "info", "gnome-shell"])
        .output()
        .ok()?;

    if output.status.success() {
        let info_str = String::from_utf8_lossy(&output.stdout);
        // Parse "Version : 45.1-1.1" from zypper info output
        for line in info_str.lines() {
            let line = line.trim();
            if line.starts_with("Version") {
                if let Some(version_part) = line.split(':').nth(1) {
                    return parse_major_version(version_part.trim());
                }
            }
        }
    }
    None
}

/// Detect GNOME version from APT cache (Debian, Ubuntu)
fn detect_from_apt_cache() -> Option<u32> {
    let output = Command::new("apt-cache")
        .args(["show", "gnome-shell"])
        .output()
        .ok()?;

    if output.status.success() {
        let info_str = String::from_utf8_lossy(&output.stdout);
        // Parse "Version: 46.0-1ubuntu1" from apt-cache output
        for line in info_str.lines() {
            if line.starts_with("Version:") {
                if let Some(version_part) = line.strip_prefix("Version:") {
                    return parse_major_version(version_part.trim());
                }
            }
        }
    }
    None
}

/// Read /etc/os-release and return key-value pairs
fn read_os_release() -> Option<std::collections::HashMap<String, String>> {
    let content = fs::read_to_string("/etc/os-release").ok()?;
    let mut map = std::collections::HashMap::new();

    for line in content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            // Remove quotes from value
            let value = value.trim_matches('"').trim_matches('\'');
            map.insert(key.to_string(), value.to_string());
        }
    }

    Some(map)
}

/// Infer GNOME version based on distribution and version
/// This is the fallback when we can't query package managers
fn infer_from_os_release() -> Option<u32> {
    let os_info = read_os_release()?;

    let id = os_info.get("ID").map(|s| s.as_str()).unwrap_or("");
    let version_id = os_info.get("VERSION_ID").map(|s| s.as_str()).unwrap_or("");
    let id_like = os_info.get("ID_LIKE").map(|s| s.as_str()).unwrap_or("");
    let pretty_name = os_info.get("PRETTY_NAME").map(|s| s.as_str()).unwrap_or("");

    // Check for rolling release distros first - these always have latest GNOME
    match id {
        // openSUSE Tumbleweed - rolling release, always latest
        "opensuse-tumbleweed" => return Some(47),
        // Fedora Rawhide - rolling release, always latest
        "fedora" if pretty_name.to_lowercase().contains("rawhide") => return Some(47),
        _ => {}
    }

    // Parse version for comparison
    let version_major: Option<u32> = version_id.split('.').next().and_then(|s| s.parse().ok());

    // Match specific distributions
    match id {
        // Ubuntu: 22.04 = GNOME 42, 24.04 = GNOME 46
        "ubuntu" => match version_id {
            "22.04" => return Some(42),
            "24.04" => return Some(46),
            _ => {
                // Future Ubuntu versions: assume modern GNOME
                // Ubuntu uses YY.MM versioning
                if let Some(year) = version_major {
                    if year >= 24 {
                        return Some(46);
                    }
                }
            }
        },

        // Debian: 12 (bookworm) = GNOME 43, 13 (trixie) = GNOME 47
        "debian" => match version_id {
            "12" => return Some(43),
            "13" => return Some(47),
            _ => {
                if let Some(v) = version_major {
                    if v >= 13 {
                        return Some(47);
                    } else if v == 12 {
                        return Some(43);
                    }
                }
            }
        },

        // Fedora: Version roughly equals GNOME version - 3
        // Fedora 40 = GNOME 46, 41 = GNOME 47, 42 = GNOME 48, etc.
        "fedora" => {
            if let Some(v) = version_major {
                // Fedora version - 6 gives approximate GNOME version
                // F40=G46, F41=G47, F42=G48, etc.
                return Some(v.saturating_add(6));
            }
        }

        // Rocky Linux / AlmaLinux / RHEL
        "rocky" | "almalinux" | "rhel" | "centos" => match version_major {
            Some(8) => return Some(40), // RHEL 8 has GNOME 40 (or 3.32 in early versions)
            Some(9) => return Some(40), // RHEL 9 has GNOME 40
            Some(10) => return Some(47), // RHEL 10 expected to have GNOME 47+
            Some(v) if v > 10 => return Some(47), // Future versions: modern
            _ => {}
        },

        // SUSE Linux Enterprise
        "sles" | "sled" | "sle-micro" => {
            // SLE 15 SP* has older GNOME
            if version_id.starts_with("15") {
                return Some(41);
            }
            // SLE 16+ will have modern GNOME
            if let Some(v) = version_major {
                if v >= 16 {
                    return Some(47);
                }
            }
        }

        // openSUSE Leap
        "opensuse-leap" => {
            // Leap 15.x has older GNOME
            if version_id.starts_with("15.") {
                return Some(41);
            }
            // Leap 16+ will have modern GNOME
            if let Some(v) = version_major {
                if v >= 16 {
                    return Some(46);
                }
            }
        }

        _ => {}
    }

    // Check ID_LIKE for derivatives
    if id_like.contains("ubuntu") || id_like.contains("debian") {
        // Unknown Debian/Ubuntu derivative - try apt-cache or assume modern
        return detect_from_apt_cache();
    }

    if id_like.contains("fedora") || id_like.contains("rhel") {
        // Unknown RHEL/Fedora derivative - try dnf or assume modern
        return detect_from_dnf_repo();
    }

    if id_like.contains("suse") {
        // Unknown SUSE derivative - try zypper
        return detect_from_zypper_repo();
    }

    None
}

/// Detect the GNOME Shell version using multiple strategies
fn detect_gnome_version() -> Option<u32> {
    // Strategy 1: Check for explicit environment variable override
    if let Ok(v) = env::var("GNOME_VERSION") {
        if let Ok(version) = v.parse::<u32>() {
            println!(
                "cargo:warning=Using GNOME version from GNOME_VERSION env var: {}",
                version
            );
            return Some(version);
        }
    }

    // Strategy 2: Try running gnome-shell --version (if GNOME is installed)
    if let Some(v) = detect_from_gnome_shell() {
        println!(
            "cargo:warning=Detected GNOME version from gnome-shell binary: {}",
            v
        );
        return Some(v);
    }

    // Strategy 3: Try querying installed packages
    if let Some(v) = detect_from_rpm_installed() {
        println!(
            "cargo:warning=Detected GNOME version from installed RPM: {}",
            v
        );
        return Some(v);
    }
    if let Some(v) = detect_from_dpkg_installed() {
        println!(
            "cargo:warning=Detected GNOME version from installed DEB: {}",
            v
        );
        return Some(v);
    }

    // Strategy 4: Try querying package repositories (works without package installed)
    if let Some(v) = detect_from_dnf_repo() {
        println!("cargo:warning=Detected GNOME version from DNF repo: {}", v);
        return Some(v);
    }
    if let Some(v) = detect_from_zypper_repo() {
        println!(
            "cargo:warning=Detected GNOME version from Zypper repo: {}",
            v
        );
        return Some(v);
    }
    if let Some(v) = detect_from_apt_cache() {
        println!("cargo:warning=Detected GNOME version from APT cache: {}", v);
        return Some(v);
    }

    // Strategy 5: Infer from /etc/os-release based on known distro versions
    if let Some(v) = infer_from_os_release() {
        println!(
            "cargo:warning=Inferred GNOME version from OS release: {}",
            v
        );
        return Some(v);
    }

    None
}

/// Copy a directory recursively
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

fn main() {
    // NOTE: No cargo:rerun-if-changed directives - this build script runs every time.
    // This is intentional to ensure correct builds across different package targets.

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let manifest_path = Path::new(&manifest_dir);

    // Source directories
    let src_ext_dir = manifest_path.join("src/qr-greeter@himmelblau-idm.org");
    let src_assets_dir = manifest_path.join("src");

    // Target directory for build output (used by cargo-deb and cargo-generate-rpm)
    // Place under target/release/ to avoid cargo-deb warnings about non-release paths
    // When cross-compiling (e.g. --target=aarch64-unknown-linux-gnu), cargo-deb remaps
    // target/release/ to target/<target-triple>/release/, so we must output files there.
    let workspace_root = manifest_path.parent().unwrap().parent().unwrap();
    let target = env::var("TARGET").unwrap_or_default();
    let host = env::var("HOST").unwrap_or_default();
    let target_prefix = if !target.is_empty() && target != host {
        format!("target/{}/release", target)
    } else {
        "target/release".to_string()
    };
    let build_output_dir = workspace_root
        .join(&target_prefix)
        .join("qr-greeter-build/qr-greeter@himmelblau-idm.org");

    // Clean and create the output directory
    if build_output_dir.exists() {
        fs::remove_dir_all(&build_output_dir).expect("Failed to clean build output directory");
    }
    fs::create_dir_all(&build_output_dir).expect("Failed to create build output directory");

    // Detect GNOME version
    let gnome_version = detect_gnome_version();
    let use_legacy = match gnome_version {
        Some(v) => {
            println!("cargo:warning=Detected GNOME Shell version: {}", v);
            v < GNOME_ESM_MIN_VERSION
        }
        None => {
            // Default to modern if we can't detect
            println!(
                "cargo:warning=Could not detect GNOME Shell version, defaulting to modern (GNOME 45+)"
            );
            false
        }
    };

    if use_legacy {
        println!("cargo:warning=Using legacy GNOME extension format (GNOME 40-44)");

        // Run the transpiler
        let transpiler = manifest_path.join("scripts/transpile-legacy.py");
        let status = Command::new("python3")
            .arg(&transpiler)
            .current_dir(workspace_root)
            .status()
            .expect("Failed to run transpile-legacy.py");

        if !status.success() {
            panic!("transpile-legacy.py failed with status: {}", status);
        }

        // Copy from the transpiler output
        let legacy_output =
            workspace_root.join("target/release/qr-greeter-legacy/qr-greeter@himmelblau-idm.org");
        copy_dir_recursive(&legacy_output, &build_output_dir)
            .expect("Failed to copy legacy extension files");
    } else {
        println!("cargo:warning=Using modern GNOME extension format (GNOME 45+)");

        // Copy the modern extension files
        copy_dir_recursive(&src_ext_dir, &build_output_dir)
            .expect("Failed to copy modern extension files");

        // Copy PNG assets
        for png in ["msdag.png", "ms-consumer-dag.png"] {
            let src = src_assets_dir.join(png);
            let dst = build_output_dir.join(png);
            if src.exists() {
                fs::copy(&src, &dst).expect("Failed to copy PNG asset");
            }
        }
    }
}
