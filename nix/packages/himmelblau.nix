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
  withSelinux ? false,
  callPackage,
  copyDesktopItems,
  config,
}:
let
  # TODO: make this optional
  # TODO: Permit opening multiple instances
  mkO365 = callPackage ../functions/o365.nix {
    himmelblau = config.services.himmelblau.package;
  };
in
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
        ../../scripts/test_script_echo.sh
        ../../platform
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
    copyDesktopItems
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

  preConfigure = ''
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

    mkdir -p $out/share/icons/hicolor/256x256/apps
    cp src/o365/src/*.png $out/share/icons/hicolor/256x256/apps/
  '';

  postInstall = ''
    ln -s $out/lib/libnss_himmelblau.so $out/lib/libnss_himmelblau.so.2
  ''
  + lib.optionalString withSelinux ''
    mkdir -p $out/share
    cp -r src/selinux/target/selinux $out/share/selinux
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

  desktopItems = [
    (mkO365 {
      name = "Outlook";
      url = "https://outlook.office.com/mail/";
      categories = [
        "Office"
        "Calendar"
        "Email"
      ];
    })
    (mkO365 {
      name = "Teams";
      url = "https://teams.microsoft.com/";
      categories = [
        "Office"
        "Chat"
      ];
    })
    (mkO365 {
      name = "Word";
      url = "https://word.cloud.microsoft/";
      categories = [
        "Office"
        "WordProcessor"
      ];
    })
    (mkO365 {
      name = "Excel";
      url = "https://excel.cloud.microsoft/";
      categories = [
        "Office"
        "Spreadsheet"
      ];
    })
    (mkO365 {
      name = "PowerPoint";
      url = "https://powerpoint.cloud.microsoft/";
      categories = [
        "Office"
        "Presentation"
      ];
    })
    (mkO365 {
      name = "PowerPoint";
      url = "https://powerpoint.cloud.microsoft/";
      categories = [
        "Office"
        "Presentation"
      ];
    })
    (mkO365 {
      name = "OneNote";
      url = "https://onenote.cloud.microsoft/launch/OneNote";
      categories = [
        "Office"
      ];
    })
    (mkO365 {
      name = "OneDrive";
      url = "https://www.office.com/onedrive";
      categories = [
        "Office"
        "FileTransfer"
      ];
    })
    (mkO365 {
      name = "SharePoint";
      url = "https://www.office.com/launch/sharepoint";
      categories = [
        "Office"
      ];
    })
  ];
})
