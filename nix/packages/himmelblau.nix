{
  lib,
  rustPlatform,
  pkg-config,
  checkpolicy,
  semodule-utils,
  talloc,
  tevent,
  ding-libs,
  libunistring,
  sqlite,
  openssl,
  libcap,
  ldb,
  krb5,
  pcre2,
  pam,
  dbus,
  udev,
  python3,
  nodejs,
  # o365
  teams-for-linux,
  gnugrep,
  gnused,
  makeWrapper,
  withSelinux ? false,
  withO365 ? false,
}:
rustPlatform.buildRustPackage (finalAttrs: {
  pname = "himmelblau";
  version = "3.0.0";

  src =
    with lib.fileset;
    toSource {
      root = ../../.;
      fileset = unions [
        ../../fuzz
        ../../src
        ../../man
        ../../Cargo.toml
        ../../Cargo.lock
        ../../scripts
        ../../platform
        ../../nix
        ../../docs-xml
      ];
    };

  outputs = [
    "out"
    "man"
  ];

  cargoLock = {
    lockFile = ../../Cargo.lock;
    allowBuiltinFetchGit = true;
  };

  nativeBuildInputs = [
    pkg-config
    rustPlatform.bindgenHook
    makeWrapper
    python3
    nodejs
  ]
  ++ lib.optionals withSelinux [
    checkpolicy
    semodule-utils
  ];

  buildInputs = [
    talloc
    tevent
    ding-libs
    libunistring
    sqlite.dev
    openssl.dev
    libcap.dev
    ldb.dev
    krb5.dev
    pcre2.dev
    pam
    dbus.dev
    udev.dev
  ];

  env = lib.attrsets.optionalAttrs (!withSelinux) {
    HIMMELBLAU_ALLOW_MISSING_SELINUX = "1";
  };

  postBuild = "cp -r man $man/";

  postInstall = ''
    ln -s $out/lib/libnss_himmelblau.so $out/lib/libnss_himmelblau.so.2

    mkdir -p $out/share/dbus-1/services
    mkdir -p $out/lib/mozilla/native-messaging-hosts
    mkdir -p $out/lib/chromium/native-messaging-hosts
    cp platform/debian/com.microsoft.identity.broker1.service $out/share/dbus-1/services/com.microsoft.identity.broker1.service
    cp src/sso/src/firefox/linux_entra_sso.json $out/lib/mozilla/native-messaging-hosts/linux_entra_sso.json
    cp src/sso/src/chrome/linux_entra_sso.json $out/lib/chromium/native-messaging-hosts/linux_entra_sso.json

    substituteInPlace \
        $out/lib/mozilla/native-messaging-hosts/linux_entra_sso.json \
        $out/lib/chromium/native-messaging-hosts/linux_entra_sso.json \
         --replace-fail "/usr/bin/" "$out/bin/"

    substituteInPlace \
        $out/share/dbus-1/services/com.microsoft.identity.broker1.service \
         --replace-fail "/usr/sbin/" "$out/bin/"
  ''
  + lib.optionalString withSelinux ''
    mkdir -p $out/share
    cp -r src/selinux/target/selinux $out/share/selinux
  ''
  + lib.optionalString withO365 ''
    mkdir -p $out/share/icons/hicolor/256x256/apps
    cp src/o365/src/*.png $out/share/icons/hicolor/256x256/apps/

    mkdir -p $out/share/applications
    cp src/o365/generated/* $out/share/applications/
    cp src/o365/src/o365-url-handler.sh $out/bin/o365-url-handler
    cp src/o365/src/o365-multi.sh $out/bin/o365-multi
    cp nix/packages/files/o365.sh $out/bin/o365
    chmod +x $out/bin/o365

    substituteInPlace $out/bin/o365 \
      --replace-fail "teams-for-linux" "${teams-for-linux}/bin/teams-for-linux"

    substituteInPlace \
      $out/bin/o365-url-handler \
      $out/bin/o365-multi \
      --replace-fail "/usr/bin/o365" "$out/bin/o365"

    substituteInPlace $out/bin/o365-url-handler \
      --replace-fail "/usr/share/" "$out/share/"


    wrapProgram $out/bin/o365-multi \
      --prefix PATH : ${
        lib.makeBinPath [
          gnugrep
          gnused
        ]
      }
  '';

  postFixup = lib.optionalString withO365 ''
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

  meta = {
    description = "Himmelblau is an interoperability suite for Microsoft Azure Entra ID and Intune.";
    homepage = "https://github.com/himmelblau-idm/himmelblau";
    license = lib.licenses.gpl3Plus;
    maintainers = [
      {
        name = "David Mulder";
        email = "dmulder@samba.org";
        github = "dmulder";
      }
    ];
    platforms = lib.platforms.linux;
  };

})
