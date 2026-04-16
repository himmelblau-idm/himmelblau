{ system ? builtins.currentSystem }:
let
  self = import ./default.nix { inherit system; };
  inherit (self.passthru) pkgs;
in
pkgs.mkShell {
  packages = with pkgs; [
    rust-analyzer
    rustfmt
    clippy
    pkg-config
    openssl
    udev.dev
    dbus.dev
    libunistring
    libclang
    clang
    stdenv.cc
    pam
    sqlite.dev
  ];

  env = {
    # For rust-analyzer support
    RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
    LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
    BINDGEN_EXTRA_CLANG_ARGS = ''
      -isystem ${pkgs.stdenv.cc.libc.dev}/include
      -isystem ${pkgs.stdenv.cc.libc.dev}/include-fixed
      -isystem ${pkgs.libcxx.dev}/include
    '';
  };
}
