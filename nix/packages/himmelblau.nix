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
