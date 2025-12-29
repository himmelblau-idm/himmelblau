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
})
