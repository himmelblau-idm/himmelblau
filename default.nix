{
  system ? builtins.currentSystem,
  sources ? import ./sources.nix,
  pkgs ? import sources.nixpkgs {
    inherit system;
  },
  lib ? pkgs.lib,
}:
let
  unistring = {
    extraRustcOptsForBuildRs = [
      "-l"
      "unistring"
    ];
    buildInputs = [
      pkgs.libunistring
    ];
  };
  cargo_nix = pkgs.callPackage ./Cargo.nix {
    buildRustCrateForPkgs =
      pkgs:
      pkgs.buildRustCrate.override {
        defaultCrateOverrides = pkgs.defaultCrateOverrides // {
          idmap =
            attrs:
            unistring
            // {
              LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
              BINDGEN_EXTRA_CLANG_ARGS = pkgs.lib.concatStringsSep " " [
                "-isystem ${pkgs.llvmPackages.libclang.lib}/lib/clang/${pkgs.llvmPackages.libclang.version}/include"
                "-isystem ${pkgs.glibc.dev}/include"
              ];
            };
          hidapi = attrs: {
            nativeBuildInputs = [
              pkgs.pkg-config
            ];
            buildInputs = [
              pkgs.udev
            ];
          };
          himmelblau_unix_common = attrs: {
            nativeBuildInputs = (if attrs ? nativeBuildInputs then attrs.nativeBuildInputs else [ ]) ++ [
              pkgs.python3
              pkgs.gettext
            ];
          };
          himmelblaud =
            attrs:
            unistring
            // {
              nativeBuildInputs = (if attrs ? nativeBuildInputs then attrs.nativeBuildInputs else [ ]) ++ [
                pkgs.gettext
                pkgs.makeWrapper
              ];
              postInstall = (if attrs ? postInstall then attrs.postInstall else "") + ''
                po_dir=${./po}
                linguas="$po_dir/LINGUAS"
                if [ -f "$linguas" ]; then
                  while IFS= read -r raw; do
                    lang="''${raw%%#*}"
                    lang="$(printf '%s' "$lang" | xargs)"
                    [ -n "$lang" ] || continue

                    po="$po_dir/$lang.po"
                    if [ ! -f "$po" ]; then
                      echo "po/LINGUAS lists $lang, but $po is missing" >&2
                      exit 1
                    fi

                    mo="$out/share/locale/$lang/LC_MESSAGES/himmelblau.mo"
                    mkdir -p "$(dirname "$mo")"
                    msgfmt --check-format --output-file "$mo" "$po"
                  done < "$linguas"
                fi

                for bin in himmelblaud himmelblaud_tasks; do
                  if [ -x "$out/bin/$bin" ]; then
                    wrapProgram "$out/bin/$bin" \
                      --set HIMMELBLAU_LOCALEDIR "$out/share/locale"
                  fi
                done
              '';
            };
          aad-tool =
            attrs:
            unistring
            // {
            };
          broker =
            attrs:
            unistring
            // {
              postInstall = ''
                mv $out/bin/broker $out/bin/himmelblau_broker

                mkdir -p $out/share/dbus-1/services
                cp platform/com.microsoft.identity.broker1.service $out/share/dbus-1/services/com.microsoft.identity.broker1.service
                substituteInPlace \
                    $out/share/dbus-1/services/com.microsoft.identity.broker1.service \
                     --replace-fail "/usr/sbin/" "$out/bin/"
              '';
            };
          sso = attrs: {
            postInstall = ''
              mkdir -p $out/lib/mozilla/native-messaging-hosts
              mkdir -p $out/lib/chromium/native-messaging-hosts
              cp src/firefox/linux_entra_sso.json $out/lib/mozilla/native-messaging-hosts/linux_entra_sso.json
              cp src/chrome/linux_entra_sso.json $out/lib/chromium/native-messaging-hosts/linux_entra_sso.json

              substituteInPlace \
                  $out/lib/mozilla/native-messaging-hosts/linux_entra_sso.json \
                  $out/lib/chromium/native-messaging-hosts/linux_entra_sso.json \
                   --replace-fail "/usr/bin/" "$out/bin/"
            '';
          };

          pam_himmelblau = attrs: {
            extraRustcOptsForBuildRs = [
              "-l"
              "unistring"
            ];
            buildInputs = [
              pkgs.libunistring
              pkgs.pam
            ];
          };

          nss_himmelblau =
            attrs:
            unistring
            // {
              postInstall = ''
                ln -s $lib/lib/libnss_himmelblau.so $lib/lib/libnss_himmelblau.so.2
              '';
            };

          o365 = attrs: {
            nativeBuildInputs = [ pkgs.makeWrapper ];
            postInstall = ''
              mkdir -p $out/share/icons/hicolor/256x256/apps
              cp src/*.png $out/share/icons/hicolor/256x256/apps/

              mkdir -p $out/share/applications
              mkdir $out/bin
              cp generated/* $out/share/applications/
              cp src/o365-url-handler.sh $out/bin/o365-url-handler
              cp src/o365-multi.sh $out/bin/o365-multi
              cp src/nix-o365.sh $out/bin/o365
              chmod +x $out/bin/o365

              substituteInPlace $out/bin/o365 \
                --replace-fail "teams-for-linux" "${pkgs.teams-for-linux}/bin/teams-for-linux"

              substituteInPlace \
                $out/bin/o365-url-handler \
                $out/bin/o365-multi \
                --replace-fail "/usr/bin/o365" "$out/bin/o365"

              substituteInPlace $out/bin/o365-url-handler \
                --replace-fail "/usr/share/" "$out/share/"


              wrapProgram $out/bin/o365-multi \
                --prefix PATH : ${
                  lib.makeBinPath [
                    pkgs.gnugrep
                    pkgs.gnused
                  ]
                }
            '';
            postFixup = ''
              substituteInPlace \
                $out/share/applications/o365-excel.desktop \
                $out/share/applications/o365-onedrive.desktop \
                $out/share/applications/o365-onenote.desktop \
                $out/share/applications/o365-outlook.desktop \
                $out/share/applications/o365-powerpoint.desktop \
                $out/share/applications/o365-sharepoint.desktop \
                $out/share/applications/o365-teams.desktop \
                $out/share/applications/o365-word.desktop \
                --replace-fail "/usr/bin/" "$out/bin/" \
                --replace-fail "/usr/share/" "$out/share/"
            '';
          };
        };
      };
  };
in
rec {

  nixosModules.himmelblau = {
    imports = [ ./nix/modules/himmelblau.nix ];
    services.himmelblau = {
      daemonPackage = pkgs.lib.mkDefault packages.daemon;
      ssoPackage = pkgs.lib.mkDefault packages.sso;
      brokerPackage = pkgs.lib.mkDefault packages.broker;
      pamPackage = pkgs.lib.mkDefault packages.pam;
      nssPackage = pkgs.lib.mkDefault packages.nss;
    };
  };

  packages = {
    daemon = cargo_nix.workspaceMembers."himmelblaud".build;
    aad-tool = cargo_nix.workspaceMembers."aad-tool".build;
    sso = cargo_nix.workspaceMembers."sso".build;
    broker = cargo_nix.workspaceMembers."broker".build;
    o365 = cargo_nix.workspaceMembers."o365".build;
    pam = cargo_nix.workspaceMembers."pam_himmelblau".build;
    nss = cargo_nix.workspaceMembers."nss_himmelblau".build;
  };

  passthru = { inherit pkgs; };
}
