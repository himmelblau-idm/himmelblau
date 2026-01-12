let
  self = import ./default.nix { };
  inherit (self.passthru) pkgs;
in
pkgs.mkShell {
  packages = with pkgs; [
    rust-analyzer
    rustfmt
    clippy
  ];

  env = {
    # For rust-analyzer support
    RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
  };
}
