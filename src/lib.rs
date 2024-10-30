use std::io::{ErrorKind, Read};
use testresult::TestResult;

const MAGIC: &[u8] = b"_NETHSM_BACKUP_";

fn get_length(r: &mut impl Read) -> std::io::Result<usize> {
    let mut len: [u8; 3] = [0; 3];
    r.read_exact(&mut len)?;
    let len0 = (len[0] as usize) << 16;
    let len1 = (len[1] as usize) << 8;
    let len2 = len[2] as usize;
    let len = len0 + len1 + len2;
    Ok(len)
}

fn get_field(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let len = get_length(r)?;
    let mut field = vec![0; len];
    r.read_exact(&mut field)?;
    Ok(field)
}

#[derive(Debug)]
pub struct Backup {
    salt: Vec<u8>,
    encrypted_version: Vec<u8>,
    encrypted_domain_key: Vec<u8>,
    items: Vec<Vec<u8>>,
}

pub fn validate(mut r: impl Read) -> std::io::Result<Backup> {
    let mut magic = [0; MAGIC.len()];
    r.read_exact(&mut magic)?;
    assert_eq!(MAGIC, magic, "Data does not contain a NetHSM header");
    let mut version = [0; 1];
    r.read_exact(&mut version)?;
    assert_eq!(
        version[0], 0,
        "Version mismatch on export, provided backup version is {}, this tool expects 0",
        version[0],
    );

    let salt = get_field(&mut r)?;
    let encrypted_version = get_field(&mut r)?;
    let encrypted_domain_key = get_field(&mut r)?;

    let mut items = vec![];
    loop {
        match get_length(&mut r) {
            Ok(len) => {
                let mut field = vec![0; len];
                r.read_exact(&mut field)?;
                items.push(field);
            }
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => {
                break;
            }
            Err(error) => {
                return Err(error);
            }
        }
    }

    Ok(Backup {
        salt,
        encrypted_version,
        encrypted_domain_key,
        items,
    })
}

use aes_gcm::aead::Aead;

pub fn decrypt(cipher: &impl Aead, bytes: &[u8], aad: &[u8]) -> TestResult<Vec<u8>> {
    let (nonce, msg) = bytes.split_at(12);

    let payload = aes_gcm::aead::Payload { msg, aad };

    let decrypted = cipher.decrypt(nonce.into(), payload)?;
    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use aes_gcm::{Aes256Gcm, Key, KeyInit as _};
    use scrypt::{scrypt, Params};

    use super::*;

    #[test]
    fn import_backup() -> testresult::TestResult {
        let backup = std::fs::File::open("tests/nethsm.backup-file.bkp")?;
        let pwd = b"my-very-unsafe-backup-passphrase";

        let backup = validate(backup)?;

        let mut key = [0; 32];
        scrypt(pwd, &backup.salt, &Params::new(14, 8, 16, 32)?, &mut key)?;
        assert_eq!(
            key,
            [
                16, 217, 215, 157, 193, 236, 87, 25, 83, 202, 109, 132, 66, 139, 7, 7, 186, 224,
                163, 117, 87, 186, 210, 36, 254, 200, 148, 170, 245, 248, 130, 158
            ]
        );
        let key: &Key<Aes256Gcm> = &key.into();
        let cipher = Aes256Gcm::new(&key);
        let version = decrypt(&cipher, &backup.encrypted_version, b"backup-version")?;

        assert_eq!(version, [0]);

        let domain_key = decrypt(&cipher, &backup.encrypted_domain_key, b"domain-key")?;
        assert_eq!(
            domain_key,
            [
                76, 254, 52, 164, 253, 191, 82, 135, 7, 229, 226, 14, 247, 246, 29, 71, 205, 151,
                210, 204, 201, 50, 58, 12, 39, 94, 79, 53, 134, 148, 211, 193, 22, 176, 22, 30, 60,
                17, 56, 9, 28, 225, 0, 186, 149, 103, 197, 117, 133, 245, 199, 136, 85, 64, 255,
                111, 170, 137, 158, 184
            ]
        );

        let mut map = HashMap::new();
        for item in backup.items {
            let decrypted = decrypt(&cipher, &item, b"backup")?;
            let mut c = std::io::Cursor::new(decrypted);
            let k = get_field(&mut c)?;
            let mut v = vec![];
            c.read_to_end(&mut v)?;
            map.insert(String::from_utf8(k)?, v);
        }
        assert_eq!(map.len(), 46);
        assert_eq!(map.get("/config/unattended-boot"), Some(vec![49].as_ref()));
        assert_eq!(map.get("/config/version"), Some(vec![48].as_ref()));

        Ok(())
    }
}
