[![Donate to Our Collective](https://opencollective.com/yourproject/donate/button.png?color=blue)](https://opencollective.com/himmelblau)

# Himmelblau

Himmelblau is an interoperability suite for Microsoft Azure Entra ID and Intune.

The name of the project comes from a German word for Azure (sky blue).

Himmelblau supports Linux authentication to Microsoft Azure Entra ID via PAM and NSS modules.
The PAM and NSS modules communicate with Entra ID via the himmelblaud daemon. Himmelblau plans to
enforce Intune MDM policies, but this work isn't completed yet.

[![sambaXP 2024: Bridging Worlds – Linux and Azure AD](img/sambaxp.png)](https://www.youtube.com/watch?v=G07FTKoNTRA "sambaXP 2024: Bridging Worlds – Linux and Azure AD")

## Contact

You can reach out on the [Himmelblau community matrix channel](https://matrix.to/#/#himmelblau:matrix.org)
or on the [Samba Technical community matrix channel](https://matrix.to/#/#samba-technical:matrix.org).

## Donations

If you would like to make [financial contributions](https://opencollective.com/himmelblau) to this project,
please make donations via our Open Collective page.

## Installing

Himmelblau is available for multiple Linux distributions, including openSUSE, SUSE Linux Enterprise (SLE), Fedora, Ubuntu, Debian, Red Hat Enterprise Linux (Rocky), and NixOS. Visit the [Himmelblau Downloads Page](https://himmelblau-idm.org/downloads.html) to fetch the appropriate packages for your distribution.

### openSUSE Tumbleweed
For openSUSE Tumbleweed, refresh the repositories and install Himmelblau:

```shell
sudo zypper ref && sudo zypper in himmelblau nss-himmelblau pam-himmelblau himmelblau-sso
```

### openSUSE Leap and SUSE Linux Enterprise
Add the appropriate repository for your version:

```shell
# For Leap 15.6 or SUSE Linux Enterprise 15 SP6:
sudo zypper ar https://download.opensuse.org/repositories/network:/idm/15.6/network:idm.repo

# For Leap 15.5 or SUSE Linux Enterprise 15 SP5:
sudo zypper ar https://download.opensuse.org/repositories/network:/idm/15.5/network:idm.repo
```

Then refresh and install:

```shell
sudo zypper ref && sudo zypper in himmelblau nss-himmelblau pam-himmelblau himmelblau-sso
```

### Fedora and RHEL (including Rocky Linux)
Download the RPMs from the [Downloads Page](https://himmelblau-idm.org/downloads.html) and install:

```shell
sudo dnf install ./himmelblau-<version>.rpm ./himmelblau-sshd-config-<version>.rpm ./himmelblau-sso-<version>.rpm ./nss-himmelblau-<version>.rpm ./pam-himmelblau-<version>.rpm
```

### Debian and Ubuntu
Download the DEB packages and install:

```shell
sudo apt install ./himmelblau_<version>.deb ./himmelblau-sshd-config_<version>.deb ./himmelblau-sso_<version>.deb ./nss-himmelblau_<version>.deb ./pam-himmelblau_<version>.deb
```

### NixOS

Himmelblau provides 2 packages and a module:

* `himmelblau.packages.<arch>.himmelblau`: The core authentication daemon intended for server deployments. (default package)
* `himmelblau.packages.<arch>.himmelblau-desktop`: The daemon and GUI tools for 2FA signin within a (GTK) desktop environment.
* `himmelblau.modules.himmelblau`: A NixOS Module that provides the most common options and service definitions.

#### Enabling the himmelblau cachix cache

Himmelblau builds our packages in CI and uploads them to [Cachix](https://www.cachix.org/) so you don't have to compile the software on every update.
We sign these binaries before upload, and the cachix client will configure nix to trust our public signing key.

```sh
$ nix profile install 'nixpkgs#cachix'
$ cachix use himmelblau
```

#### Classic Nixos configurations

Classic NixOS configurations can use the `builtins.getFlake` function if they have enabled `flakes` compatability.

```nix
{lib, ...}:
let himmelblau = builtins.getFlake "github:himmelblau-idm/himmelblau/0.9.0";
in {
    imports = [ himmelblau.nixosModules.himmelblau ];

    services.himmelblau.enable = true;
    services.himmelblau.settings = {
        domains = ["my.domain.net"];
        pam_allow_groups = [ "ENTRA-GROUP-GUID-HERE" ];
        local_groups = [ "wheel" "docker" ];
    };
}
```

#### Flake based configurations

Flake based configurations add this repository to their inputs, enable the service, provide the minimal set of options.

```nix
{
    inputs = {
        nixpkgs.url = "github:nixos/nixpkgs/nixos-24.11";
        himmelblau.url = "github:himmelblau-idm/himmelblau/main";
        himmelblau.inputs.nixpkgs.follows = "nixpkgs";
    };
    outputs = { self, nixpkgs, himmelblau }: {
        nixosModules.azureEntraId = {
            imports = [ himmelblau.nixosModules.himmelblau ];
            services.himmelblau = {
                enable = true;
                settings = {
                    domains = ["my.domain.net"];
                    pam_allow_groups = [ "ENTRA-GROUP-GUID-HERE" ];
                    local_groups = [ "wheel" "docker" ];
                };
            };
        };
        nixosConfigurations."your-machine" = nixpkgs.lib.nixosSystem {
            system = "x86_64-linux";
            modules = [
                self.nixosModules.azureEntraId
                ./machines/your-machine/configuration.nix
            ];
        };
    };
}
```

## Demos

### Windows Hello on Linux via GDM
[![Azure Entra ID Authentication for openSUSE: Windows Hello on Linux!](img/hello.png)](https://www.youtube.com/watch?v=rSeHxs0JX58 "Azure Entra ID Authentication for openSUSE: Windows Hello on Linux!")

### MFA Authentication over SSH

[![Azure Entra ID MFA Authentication over SSH: Himmelblau](img/ssh.png)](https://www.youtube.com/watch?v=IAqC8FoYLGc "Azure Entra ID MFA Authentication over SSH: Himmelblau")

## Contributing

The following packages are required on openSUSE to build and test this package.

    sudo zypper in make cargo git gcc sqlite3-devel libopenssl-3-devel pam-devel libcap-devel libtalloc-devel libtevent-devel libldb-devel libdhash-devel krb5-devel pcre2-devel libclang13 autoconf make automake  gettext-tools clang dbus-1-devel utf8proc-devel gobject-introspection-devel cairo-devel gdk-pixbuf-devel libsoup-devel pango-devel atk-devel gtk3-devel webkit2gtk3-devel libudev-devel mercurial python311-gyp


Or on Debian based systems:

    sudo apt-get install make gcc libpam0g-dev libudev-dev libssl-dev pkg-config tpm-udev libtss2-dev libcap-dev libtalloc-dev libtevent-dev libldb-dev libdhash-dev libkrb5-dev libpcre2-dev libclang-18-dev autoconf gettext libsqlite3-dev build-essentials libdbus-1-dev libutf8proc-dev

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source "$HOME/.cargo/env"
    rustup default stable

On Debian systems, rust must be installed using [rustup](https://rustup.rs), because the version of Rust shipped with Debian is very old. The package `build-essentials` may not be available. Ignore this requirement if not found.

You can build the components with

    cd himmelblau; make

Install the binaries

> **WARNING** you should only do this on a disposable machine or a machine you are willing to
> recover with single user mode.

    sudo make install

Configure your instance

    vim /etc/himmelblau/himmelblau.conf

It's essential that you configure the `domains` and `pam_allow_groups` options, otherwise
no users will be able to authenticate. These options designate the list of domains and users
or groups which are allowed access to the host.

Run the daemon with:

    sudo systemctl start himmelblaud himmelblaud-tasks

Check systemd journal for errors.

Disable nscd

    systemctl stop nscd
    systemctl disable nscd
    systemctl mask nscd

Setup NSS

    cp /usr/etc/nsswitch.conf /etc/nsswitch.conf

    # vim /etc/nsswitch.conf
    passwd:     compat systemd himmelblau
    group:      compat systemd himmelblau
    shadow:     compat systemd himmelblau

Check that you can resolve a user with

    getent passwd <name>

Setup PAM

> **WARNING** only modify your PAM configuration if you are confident you understand
> the syntax. The following setup is meant as an example. Removing PAM modules from
> your stack may prevent you from authenticating to the host. Proceed with caution!

    old /etc/pam.d/{common-account,common-auth,common-password,common-session}
    cp /etc/pam.d/common-password-pc /etc/pam.d/common-password
    cp /etc/pam.d/common-auth-pc /etc/pam.d/common-auth
    cp /etc/pam.d/common-account-pc /etc/pam.d/common-account
    cp /etc/pam.d/common-session-pc /etc/pam.d/common-session

    # vim /etc/pam.d/common-auth
    auth        required      pam_env.so
    auth        [default=1 ignore=ignore success=ok] pam_localuser.so
    auth        sufficient    pam_himmelblau.so
    auth        sufficient    pam_unix.so nullok try_first_pass
    auth        required      pam_deny.so

    # vim /etc/pam.d/common-account
    account    [default=1 ignore=ignore success=ok] pam_localuser.so
    account    sufficient    pam_himmelblau.so ignore_unknown_user
    account    sufficient    pam_unix.so
    account    required      pam_deny.so

    # vim /etc/pam.d/common-session
    session optional    pam_systemd.so
    session required    pam_limits.so
    session optional    pam_himmelblau.so
    session optional    pam_unix.so try_first_pass
    session optional    pam_umask.so
    session optional    pam_env.so
