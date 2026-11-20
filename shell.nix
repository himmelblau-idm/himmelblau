{
  system ? builtins.currentSystem,
  sources ? import ./sources.nix,
  pkgs ? import sources.nixpkgs {
    inherit system;
    overlays = [ (import sources.rust-overlay) ];
  },
}:
let
  rustVersion = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.rust-version;
  rustToolchain = pkgs.rust-bin.stable."${rustVersion}.0".default.override {
    extensions = [ "rust-analyzer" "rust-src" ];
  };
in
pkgs.mkShell {
  packages = with pkgs; [
    rustToolchain
    gawk
    pkg-config
    openssl
    udev.dev
    dbus.dev
    libunistring
    clang
    libclang
    stdenv.cc
    pam
    sqlite.dev
    python3
  ];

  env = {
    # For rust-analyzer support
    RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
    LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
    BINDGEN_EXTRA_CLANG_ARGS = ''
      -isystem ${pkgs.stdenv.cc.libc.dev}/include
      -isystem ${pkgs.stdenv.cc.libc.dev}/include-fixed
      -isystem ${pkgs.libcxx.dev}/include
    '';
  };
}
