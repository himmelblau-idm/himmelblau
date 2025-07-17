% PAM_HIMMELBLAU(8) Himmelblau PAM module | July 2025

# NAME

**pam_himmelblau** — enable Azure Entra ID authentication via Himmelblau

# SYNOPSIS

**pam_himmelblau.so** [debug] [use_first_pass] [ignore_unknown_user] [mfa_poll_prompt] [no_hello_pin]

# DESCRIPTION

**pam_himmelblau** is a PAM module that authenticates users against Microsoft Azure Entra ID using the Himmelblau daemon (`himmelblaud`).

# OPTIONS

- **debug**  
  Enables verbose logging to stdout.

- **use_first_pass**  
  Uses a password already provided by a previous PAM module as either a Linux Hello PIN or an Entra Id password, instead of prompting again.

- **ignore_unknown_user**  
  Returns `PAM_IGNORE` for users not in Entra ID, allowing fallback to local authentication via subsequent PAM modules.

- **mfa_poll_prompt**  
  Workaround for OpenSSH Bug 2876, which prevents PAM messages from being flushed to stdout until after sending a prompt for input. This workaround causes pam to prompt the user to 'press enter to continue' when polling on another device for MFA.

- **no_hello_pin**  
  Disables Linux Hello PIN login for this service (e.g., for `sudo` or `ssh`), even if Hello is configured globally.

# PAM CONFIGURATION

Configuring PAM ensures authentication requests go through Entra ID when appropriate.

## Automatic setup

On Ubuntu/Debian:

```bash
sudo pam-auth-update
```

Enable “Azure authentication” and verify PAM files.

On openSUSE Tumbleweed or SLE:

```bash
pam-config --add --himmelblau
```

The `aad-tool configure-pam` command also inserts recommended directives (dry-run unless `--really` is used).

## Manual configuration

In `/etc/pam.d/common-auth`, ensure that the `pam_himmelblau.so` module is placed after other authentication methods (such as `pam_unix.so`). Ensure that other authentication modules are not set to `required`, as this could cause authentication to fail prior to PAM communicating with Entra ID. Include the `ignore_unknown_user` option for Himmelblau. Ensure `pam_deny.so` is placed after all modules, so that unknown users are not implicitly allowed.

#### **Note:** If you intend to use Hello or Passwordless authentication, it's recommended that `pam_himmelblau.so` be placed before `pam_unix.so` in the pam `auth` stack (but always after `pam_localuser.so`), otherwise `pam_unix` will unnecessarily prompt for a password.

```pam
auth        required      pam_env.so
auth        [default=1 ignore=ignore success=ok] pam_localuser.so
auth        sufficient    pam_unix.so nullok try_first_pass
auth        sufficient    pam_himmelblau.so ignore_unknown_user
auth        required      pam_deny.so
```

Configure `/etc/pam.d/common-account` in a similar manner.

```pam
account    [default=1 ignore=ignore success=ok] pam_localuser.so
account    sufficient    pam_unix.so
account    sufficient    pam_himmelblau.so ignore_unknown_user
account    required      pam_deny.so
```

In `/etc/pam.d/common-session`, set `pam_himmelblau.so` as an optional module.

```pam
session optional    pam_systemd.so
session required    pam_limits.so
session optional    pam_unix.so try_first_pass
session optional    pam_umask.so
session optional    pam_himmelblau.so
session optional    pam_env.so
```

In `/etc/pam.d/common-password`, set `pam_himmelblau.so` as sufficient.

```pam
password	sufficient	pam_himmelblau.so ignore_unknown_user
password        optional        pam_gnome_keyring.so    use_authtok
password	sufficient	pam_unix.so	use_authtok nullok shadow try_first_pass 
password	required	pam_deny.so
```

# RETURN VALUES

- **PAM_SUCCESS**  
  Authentication or Hello PIN update succeeded.

- **PAM_AUTH_ERR**  
  Authentication failed. This may include incorrect credentials, rejected MFA, or other auth-layer failures.

- **PAM_USER_UNKNOWN**  
  The user was not found in Entra ID. This is bypassed if the `ignore_unknown_user` option is specified.

- **PAM_IGNORE**  
  The module was instructed to skip processing (e.g., due to `ignore_unknown_user`). This allows fallback to other PAM modules.

- **PAM_SERVICE_ERR**  
  A configuration or initialization error occurred in the module, or a required daemon was unreachable.

- **PAM_CRED_INSUFFICIENT**  
  The user did not meet the required credential policy.

- **PAM_ABORT**  
  A critical, unrecoverable failure occurred—such as a panic inside the `himmelblaud` service.

# SEE ALSO

**himmelblaud(8)**, **aad-tool(1)**, **himmelblau.conf(5)**, **pam(8)**

# AUTHOR

David Mulder <dmulder@himmelblau-idm.org>, <dmulder@samba.org>
