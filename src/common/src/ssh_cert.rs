//! Minimal, allocation-bounded OpenSSH certificate metadata parser used by
//! the sshd authorization path. Signature verification remains OpenSSH's job;
//! this parser binds the signed identity metadata to a Himmelblau account.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const RSA_CERT_TYPE: &str = "ssh-rsa-cert-v01@openssh.com";
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSshCertificate {
    pub key_type: String,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: u64,
    pub valid_before: u64,
    pub object_id: Uuid,
    pub tenant_id: Uuid,
    pub signing_ca_fingerprint_sha256: String,
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| "SSH certificate length overflow".to_string())?;
        if end > self.input.len() {
            return Err("truncated SSH certificate".to_string());
        }
        let value = &self.input[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| "invalid u32")?,
        ))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| "invalid u64")?,
        ))
    }

    fn string(&mut self) -> Result<&'a [u8], String> {
        let length = usize::try_from(self.u32()?).map_err(|_| "invalid string length")?;
        self.take(length)
    }

    fn text(&mut self) -> Result<String, String> {
        String::from_utf8(self.string()?.to_vec())
            .map_err(|_| "non-UTF-8 SSH certificate text".to_string())
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err("trailing SSH certificate data".to_string())
        }
    }
}

fn string_list(input: &[u8]) -> Result<Vec<String>, String> {
    let mut reader = Reader::new(input);
    let mut values = Vec::new();
    while reader.offset < input.len() {
        if values.len() >= 64 {
            return Err("too many SSH certificate principals".to_string());
        }
        values.push(reader.text()?);
    }
    reader.finish()?;
    Ok(values)
}

fn extension_text(input: &[u8]) -> Result<String, String> {
    let mut reader = Reader::new(input);
    let value = reader.text()?;
    reader.finish()?;
    Ok(value)
}

pub fn parse_ssh_certificate(body_base64: &str) -> Result<ParsedSshCertificate, String> {
    if body_base64.len() > MAX_CERTIFICATE_BYTES * 2 {
        return Err("SSH certificate exceeds size limit".to_string());
    }
    let bytes = STANDARD
        .decode(body_base64)
        .map_err(|_| "invalid SSH certificate base64".to_string())?;
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err("SSH certificate exceeds size limit".to_string());
    }

    let mut reader = Reader::new(&bytes);
    let key_type = reader.text()?;
    if key_type != RSA_CERT_TYPE {
        return Err("certificate is not an Entra-compatible RSA user certificate".to_string());
    }
    let _nonce = reader.string()?;
    let _exponent = reader.string()?;
    let _modulus = reader.string()?;
    let _serial = reader.u64()?;
    if reader.u32()? != 1 {
        return Err("SSH host certificates are not valid user credentials".to_string());
    }
    let key_id = reader.text()?;
    let principals = string_list(reader.string()?)?;
    if principals.is_empty() {
        return Err("SSH certificate contains no principal".to_string());
    }
    let valid_after = reader.u64()?;
    let valid_before = reader.u64()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock precedes Unix epoch".to_string())?
        .as_secs();
    if valid_before <= valid_after || now < valid_after || now >= valid_before {
        return Err("SSH certificate is not currently valid".to_string());
    }
    let _critical_options = reader.string()?;
    let extension_bytes = reader.string()?;
    let _reserved = reader.string()?;
    let signature_key = reader.string()?;
    let _signature = reader.string()?;
    reader.finish()?;

    let mut object_id = None;
    let mut tenant_id = None;
    let mut extensions = Reader::new(extension_bytes);
    while extensions.offset < extension_bytes.len() {
        let name = extensions.text()?;
        let value = extensions.string()?;
        match name.as_str() {
            "oid@sshservice.azure.net" => {
                if object_id.is_some() {
                    return Err("duplicate SSH certificate object ID".to_string());
                }
                object_id = Some(
                    Uuid::parse_str(&extension_text(value)?)
                        .map_err(|_| "invalid SSH certificate object ID".to_string())?,
                );
            }
            "tid@sshservice.azure.net" => {
                if tenant_id.is_some() {
                    return Err("duplicate SSH certificate tenant ID".to_string());
                }
                tenant_id = Some(
                    Uuid::parse_str(&extension_text(value)?)
                        .map_err(|_| "invalid SSH certificate tenant ID".to_string())?,
                );
            }
            _ => {}
        }
    }
    extensions.finish()?;
    let object_id = object_id.ok_or_else(|| "missing SSH certificate object ID".to_string())?;
    let tenant_id = tenant_id.ok_or_else(|| "missing SSH certificate tenant ID".to_string())?;
    if key_id != format!("{}@{}", object_id, tenant_id) {
        return Err("SSH certificate key ID does not match OID/TID".to_string());
    }

    let digest = Sha256::digest(signature_key);
    Ok(ParsedSshCertificate {
        key_type,
        key_id,
        principals,
        valid_after,
        valid_before,
        object_id,
        tenant_id,
        signing_ca_fingerprint_sha256: format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)),
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_ssh_certificate, RSA_CERT_TYPE};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use std::time::{SystemTime, UNIX_EPOCH};

    const OID: &str = "23020401-2996-4c8a-93c1-2a897f237f61";
    const TID: &str = "d2aeee75-1b7b-4211-81c0-a7320a908d8e";
    const PRINCIPAL: &str = "user@example.com";

    fn ssh_string(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
        let length = u32::try_from(value.len()).map_err(|_| "test field too long")?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(value);
        Ok(())
    }

    fn extension(output: &mut Vec<u8>, name: &str, value: &str) -> Result<(), String> {
        let mut nested = Vec::new();
        ssh_string(&mut nested, value.as_bytes())?;
        ssh_string(output, name.as_bytes())?;
        ssh_string(output, &nested)
    }

    fn certificate(cert_type: u32, key_id: &str) -> Result<String, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| err.to_string())?
            .as_secs();
        let mut principals = Vec::new();
        ssh_string(&mut principals, PRINCIPAL.as_bytes())?;
        let mut extensions = Vec::new();
        extension(&mut extensions, "oid@sshservice.azure.net", OID)?;
        extension(&mut extensions, "tid@sshservice.azure.net", TID)?;

        let mut body = Vec::new();
        ssh_string(&mut body, RSA_CERT_TYPE.as_bytes())?;
        ssh_string(&mut body, b"nonce")?;
        ssh_string(&mut body, &[1, 0, 1])?;
        ssh_string(&mut body, &[0, 0x80, 1])?;
        body.extend_from_slice(&0_u64.to_be_bytes());
        body.extend_from_slice(&cert_type.to_be_bytes());
        ssh_string(&mut body, key_id.as_bytes())?;
        ssh_string(&mut body, &principals)?;
        body.extend_from_slice(&now.saturating_sub(60).to_be_bytes());
        body.extend_from_slice(&now.saturating_add(600).to_be_bytes());
        ssh_string(&mut body, &[])?;
        ssh_string(&mut body, &extensions)?;
        ssh_string(&mut body, &[])?;
        ssh_string(&mut body, b"synthetic-ca-key")?;
        ssh_string(&mut body, b"synthetic-signature")?;
        Ok(STANDARD.encode(body))
    }

    #[test]
    fn parses_microsoft_identity_binding() -> Result<(), String> {
        let parsed = parse_ssh_certificate(&certificate(1, &format!("{OID}@{TID}"))?)?;
        assert_eq!(parsed.object_id.to_string(), OID);
        assert_eq!(parsed.tenant_id.to_string(), TID);
        assert_eq!(parsed.principals, [PRINCIPAL]);
        Ok(())
    }

    #[test]
    fn rejects_host_certificate() -> Result<(), String> {
        let result = parse_ssh_certificate(&certificate(2, &format!("{OID}@{TID}"))?);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn rejects_key_id_identity_mismatch() -> Result<(), String> {
        let result = parse_ssh_certificate(&certificate(1, "different@identity")?);
        assert!(result.is_err());
        Ok(())
    }
}
