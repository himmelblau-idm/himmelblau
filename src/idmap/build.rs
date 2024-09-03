use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let autoreconf = Command::new("./autogen.sh")
        .output()
        .expect("Failed to configure sss_idmap");
    if !autoreconf.status.success() {
        io::stdout().write_all(&autoreconf.stdout).unwrap();
        io::stderr().write_all(&autoreconf.stderr).unwrap();
        panic!("Failed to configure sss_idmap");
    }
    io::stdout().write_all(&autoreconf.stdout).unwrap();
    let configure = Command::new("./configure")
        .output()
        .expect("Failed to configure sss_idmap");
    if !configure.status.success() {
        io::stdout().write_all(&configure.stdout).unwrap();
        io::stderr().write_all(&configure.stderr).unwrap();
        panic!("Failed to configure sss_idmap");
    }
    io::stdout().write_all(&configure.stdout).unwrap();

    cc::Build::new()
        .file("sssd/src/lib/idmap/sss_idmap.c")
        .file("sssd/src/lib/idmap/sss_idmap_conv.c")
        .file("sssd/src/util/murmurhash3.c")
        .include(Path::new("/usr/include/samba-4.0"))
        .include(Path::new("sssd/src"))
        .include(Path::new("./")) // for config.h
        .warnings(false)
        .compile("sss_idmap");

    let bindings = bindgen::Builder::default()
        .blocklist_function("qgcvt")
        .blocklist_function("qgcvt_r")
        .blocklist_function("qfcvt")
        .blocklist_function("qfcvt_r")
        .blocklist_function("qecvt")
        .blocklist_function("qecvt_r")
        .blocklist_function("strtold")
        .clang_arg("-I/usr/include/samba-4.0")
        .header("wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
