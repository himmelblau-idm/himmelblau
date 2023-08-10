# Himmelblau

<p align="center">
  <img src="img/penguin.png" width="15%" height="auto" />
</p>

Himmelblau is an interoperability suite for Microsoft Azure AD and Intune.

The name of the project comes from a German word for Azure (sky blue).

Himmelblau supports Linux authentication to Microsoft Azure AD (AAD) via PAM and NSS modules.
The PAM and NSS modules communicate with AAD via the himmelblaud daemon. Himmelblau also
enforces Intune MDM policies.

## Contributing

The following packages are required on opensuse to build and test this package.

    zypper in cargo git sqlite3-devel libopenssl-3-devel pam-devel python3-devel

You can build the components with

    cd himmelblau
    cargo build

To test debug builds you can use these directly out of the build directory, but you must
link the libraries to the correct locations

> **WARNING** you should only do this on a disposable machine or a machine you are willing to
> recover with single user mode.

    # You must use the full paths!
    ln -s /root/himmelblau/target/debug/libpam_himmelblau.so /usr/lib64/security/pam_himmelblau.so
    ln -s /root/himmelblau/target/debug/libnss_himmelblau.so /usr/lib64/libnss_himmelblau.so.2

Configure your instance

    mkdir /etc/himmelblau/
    cp src/himmelblaud/config/himmelblau.conf.example /etc/himmelblau/himmelblau.conf
    vim /etc/himmelblau/himmelblau.conf

Run the daemon with:

    cargo run -- -d

Check systemd journal for errors.

Disable nscd

    systemctl stop nscd
    systemctl disable nscd
    systemctl mask nscd

Setup NSS

    cp /usr/etc/nsswitch.conf /etc/nsswitch.conf

    # vim /etc/nsswitch.conf
    passwd:     compat himmelblau
    group:      compat himmelblau
    shadow:     compat himmelblau

Check that you can resolve a user with

    getent passwd <name>

Setup PAM

    rm /etc/pam.d/{common-account,common-auth,common-password,common-session}
    cp /etc/pam.d/common-password-pc /etc/pam.d/common-password
    cp /etc/pam.d/common-auth-pc /etc/pam.d/common-auth
    cp /etc/pam.d/common-account-pc /etc/pam.d/common-account
    cp /etc/pam.d/common-session-pc /etc/pam.d/common-session

    # vim /etc/pam.d/common-auth
    auth        required      pam_env.so
    auth        [default=1 ignore=ignore success=ok] pam_localuser.so
    auth        sufficient    pam_unix.so nullok try_first_pass
    auth        sufficient    pam_himmelblau.so ignore_unknown_user
    auth        required      pam_deny.so

    # vim /etc/pam.d/common-account
    account    [default=1 ignore=ignore success=ok] pam_localuser.so
    account    sufficient    pam_unix.so
    account    sufficient    pam_himmelblau.so ignore_unknown_user
    account    required      pam_deny.so

    # vim /etc/pam.d/common-session
    session required    pam_mkhomedir.so
    session optional    pam_systemd.so
    session required    pam_limits.so
    session optional    pam_unix.so try_first_pass
    session optional    pam_umask.so
    session optional    pam_himmelblau.so
    session optional    pam_env.so

Be sure to include `pam_mkhomedir.so` in the pam session configuration, or your home directory will not be created.
