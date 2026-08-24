use himmelblau_unix_common::client_sync::DaemonClientBlocking;
use himmelblau_unix_common::constants::DEFAULT_SOCK_PATH;
use himmelblau_unix_common::unix_proto::{ClientRequest, ClientResponse};

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let target_account = args.next().ok_or("missing target account")?;
    let target_uid: u32 = args.next().ok_or("missing target UID")?.parse()?;
    let openssh_key_id = args.next().ok_or("missing certificate key ID")?;
    let openssh_ca_fingerprint = args.next().ok_or("missing CA fingerprint")?;
    let certificate_type = args.next().ok_or("missing certificate type")?;
    let certificate_body_base64 = args.next().ok_or("missing certificate body")?;
    if args.next().is_some() {
        return Err("unexpected authorization arguments".into());
    }

    let mut client = DaemonClientBlocking::new(DEFAULT_SOCK_PATH)?;
    let validated = client.call_and_wait(
        &ClientRequest::ValidateSshCertificateForAccount {
            target_account,
            target_uid,
            certificate_type,
            certificate_body_base64,
            openssh_key_id,
            openssh_ca_fingerprint,
        },
        10,
    )?;
    let ClientResponse::SshValidatedIdentity(identity) = validated else {
        return Err("certificate identity validation denied".into());
    };

    // This is intentionally the existing PAM account-policy request rather
    // than a parallel SSH-only policy implementation.
    let policy = client.call_and_wait(
        &ClientRequest::PamAccountAllowed(identity.canonical_upn),
        10,
    )?;
    if !matches!(policy, ClientResponse::PamStatus(Some(true))) {
        return Err("Himmelblau account policy denied SSH access".into());
    }

    println!("{}", identity.authorized_principal);
    Ok(())
}

fn main() {
    if run().is_err() {
        // AuthorizedPrincipalsCommand denies by emitting no principals. Avoid
        // printing certificate or identity material to stderr/auth logs.
        std::process::exit(1);
    }
}
