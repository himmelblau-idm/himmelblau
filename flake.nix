{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system};
          rustPlatform = pkgs.rustPlatform;
          cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
          recipe = {lib, enableInteractive ? false}: rustPlatform.buildRustPackage {
            pname = "himmelblau";
            version = cargoToml.workspace.package.version;
            src = with lib.fileset; toSource {
              root = ./.;
              fileset = difference (gitTracked ./.) (fileFilter
                (file: file.hasExt "nix" || file.hasExt "md" || file == "Makefile") ./.);
            };
            outputs = [ "out" "man" ];
            cargoLock = {
              lockFile = ./Cargo.lock;
              allowBuiltinFetchGit = true;
            };

            buildFeatures = lib.optionals enableInteractive [ "interactive" ];
            nativeBuildInputs = [
              pkgs.pkg-config rustPlatform.bindgenHook
            ];
            buildInputs = with pkgs; [
              talloc tevent ding-libs utf8proc
              sqlite.dev openssl.dev libcap.dev
              ldb.dev krb5.dev pcre2.dev
              pam dbus.dev udev.dev
            ] ++ lib.optionals enableInteractive [
              gobject-introspection.dev cairo.dev gdk-pixbuf.dev
              libsoup.dev pango.dev atk.dev gtk3.dev webkitgtk_4_1
            ];
            postBuild = "cp -r man $man/";
            postInstall = "ln -s $out/lib/libnss_himmelblau.so $out/lib/libnss_himmelblau.so.2";
            meta = with lib; {
              description = "Himmelblau is an interoperability suite for Microsoft Azure Entra ID and Intune.";
              homepage = "https://github.com/himmelblau-idm/himmelblau";
              license = licenses.gpl3Plus;
              maintainers = [{
                name = "David Mulder";
                email = "dmulder@samba.org";
                github = "dmulder";
              }];
              platforms = platforms.linux;
            };
          };
      in rec {
        packages.himmelblau = pkgs.callPackage recipe {};
        packages.himmelblau-desktop = pkgs.callPackage recipe { enableInteractive = true; };
        packages.default = packages.himmelblau;

        devShells.default = pkgs.mkShell {
          name = "himmelblau-devshell";
          inputsFrom = [ packages.himmelblau-desktop ];
          nativeBuildInputs = with pkgs; [ rust-analyzer rustfmt clippy ];
        };
      });
}
