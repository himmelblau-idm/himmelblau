/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

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
#[cfg(not(feature = "no_sssd_idmap"))]
use std::env;
#[cfg(not(feature = "no_sssd_idmap"))]
use std::path::PathBuf;

#[cfg(feature = "no_sssd_idmap")]
fn main() { }

#[cfg(not(feature = "no_sssd_idmap"))]
fn main() {
    cc::Build::new()
        .file("src/sss_idmap.c")
        .file("src/sss_idmap_conv.c")
        .file("src/murmurhash3.c")
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
        .header("src/sss_idmap.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
    println!("cargo:rustc-link-lib=utf8proc");
    println!("cargo:rustc-env=LD_LIBRARY_PATH=../../bin/shared/private/");
}
