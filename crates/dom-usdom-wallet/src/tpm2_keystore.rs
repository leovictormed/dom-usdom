//! TPM2-backed second factor for operational wallet snapshot encryption.
//!
//! The human recovery password continues to protect the portable recovery
//! seed. Operational snapshots use a distinct passphrase derived from that
//! password, a release/wallet binding and a random secret readable only from
//! one authenticated TPM NV index.

use std::{
    ffi::OsString,
    fs::File,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use fs2::FileExt;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    tpm2_authority::{
        auth_argument, io_error, open_private_lock, run_command, validate_index,
        validate_public_output, SecretMemfd, TPM2_DEVICE, TPM2_NVDEFINE, TPM2_NVREAD,
        TPM2_NVREADPUBLIC, TPM2_NVWRITE,
    },
    Tpm2AuthorityBinding, Tpm2NvAuthorization, Tpm2SealAuthorityError, WalletPassphrase,
};

const RECORD_MAGIC: &[u8; 8] = b"USWKEY01";
const RECORD_VERSION: u16 = 1;
const RECORD_PREFIX_BYTES: usize = 8 + 2 + 4 + 32 + 32;
const RECORD_BYTES: usize = RECORD_PREFIX_BYTES + 32;
const RECORD_HASH_DOMAIN: &[u8] = b"DOM:usdom-wallet:tpm2-keystore-record:v1";
const PASSPHRASE_KDF_INFO: &[u8] = b"DOM:usdom-wallet:tpm2-operational-passphrase:v1";

/// Fixed TPM2 NV handle holding the operational-wallet hardware secret.
pub const USDOM_TPM2_KEYSTORE_NV_INDEX: u32 = 0x0155_5345;

trait KeystoreBackend {
    fn validate_public(&mut self, written: bool) -> Result<(), Tpm2SealAuthorityError>;
    fn define(&mut self, owner_authorization: &[u8]) -> Result<(), Tpm2SealAuthorityError>;
    fn read(&mut self) -> Result<Zeroizing<Vec<u8>>, Tpm2SealAuthorityError>;
    fn write(&mut self, bytes: &[u8]) -> Result<(), Tpm2SealAuthorityError>;
}

struct CommandKeystoreBackend {
    index: u32,
    authorization: Tpm2NvAuthorization,
}

/// Hardware-backed second factor used to derive wallet snapshot passphrases.
pub struct Tpm2WalletKeystore {
    index: u32,
    binding: Tpm2AuthorityBinding,
    lock: File,
    backend: Box<dyn KeystoreBackend>,
}

struct KeystoreRecord {
    index: u32,
    binding: Tpm2AuthorityBinding,
    secret: Zeroizing<[u8; 32]>,
}

impl KeystoreRecord {
    fn generate(index: u32, binding: Tpm2AuthorityBinding) -> Result<Self, Tpm2SealAuthorityError> {
        let mut secret = Zeroizing::new([0u8; 32]);
        loop {
            rand::rngs::OsRng
                .try_fill_bytes(&mut secret[..])
                .map_err(|_| Tpm2SealAuthorityError::RandomnessUnavailable)?;
            if secret.iter().any(|byte| *byte != 0) {
                break;
            }
        }
        Ok(Self {
            index,
            binding,
            secret,
        })
    }

    fn encode(&self) -> Zeroizing<[u8; RECORD_BYTES]> {
        let mut bytes = Zeroizing::new([0u8; RECORD_BYTES]);
        bytes[..8].copy_from_slice(RECORD_MAGIC);
        bytes[8..10].copy_from_slice(&RECORD_VERSION.to_be_bytes());
        bytes[10..14].copy_from_slice(&self.index.to_be_bytes());
        bytes[14..46].copy_from_slice(&self.binding.as_bytes());
        bytes[46..78].copy_from_slice(&self.secret[..]);
        let digest = record_digest(&bytes[..RECORD_PREFIX_BYTES]);
        bytes[RECORD_PREFIX_BYTES..].copy_from_slice(&digest);
        bytes
    }

    fn decode(
        bytes: &[u8],
        expected_index: u32,
        expected_binding: Tpm2AuthorityBinding,
    ) -> Result<Self, Tpm2SealAuthorityError> {
        if bytes.len() != RECORD_BYTES
            || &bytes[..8] != RECORD_MAGIC
            || u16::from_be_bytes(
                bytes[8..10]
                    .try_into()
                    .map_err(|_| Tpm2SealAuthorityError::InvalidRecord)?,
            ) != RECORD_VERSION
            || u32::from_be_bytes(
                bytes[10..14]
                    .try_into()
                    .map_err(|_| Tpm2SealAuthorityError::InvalidRecord)?,
            ) != expected_index
            || bytes[14..46] != expected_binding.as_bytes()
            || bytes[46..78].iter().all(|byte| *byte == 0)
            || bytes[RECORD_PREFIX_BYTES..] != record_digest(&bytes[..RECORD_PREFIX_BYTES])
        {
            return Err(Tpm2SealAuthorityError::InvalidRecord);
        }
        let secret = Zeroizing::new(
            bytes[46..78]
                .try_into()
                .map_err(|_| Tpm2SealAuthorityError::InvalidRecord)?,
        );
        let record = Self {
            index: expected_index,
            binding: expected_binding,
            secret,
        };
        if record.encode().as_slice() != bytes {
            return Err(Tpm2SealAuthorityError::InvalidRecord);
        }
        Ok(record)
    }

    fn commitment(&self) -> [u8; 32] {
        record_digest(&self.encode()[..RECORD_PREFIX_BYTES])
    }
}

impl Tpm2WalletKeystore {
    /// Open an existing exact wallet-bound hardware keystore.
    pub fn open(
        index: u32,
        binding: Tpm2AuthorityBinding,
        authorization: Tpm2NvAuthorization,
        lock_path: &Path,
    ) -> Result<Self, Tpm2SealAuthorityError> {
        validate_index(index)?;
        let lock = open_private_lock(lock_path)?;
        let mut keystore = Self {
            index,
            binding,
            lock,
            backend: Box::new(CommandKeystoreBackend {
                index,
                authorization,
            }),
        };
        keystore.with_lock(|this| this.read_record().map(|_| ()))?;
        Ok(keystore)
    }

    /// Define and initialize the keystore, or authenticate an idempotent retry.
    pub fn initialize(
        index: u32,
        binding: Tpm2AuthorityBinding,
        authorization: Tpm2NvAuthorization,
        owner_authorization: Zeroizing<Vec<u8>>,
        lock_path: &Path,
    ) -> Result<Self, Tpm2SealAuthorityError> {
        validate_index(index)?;
        if owner_authorization.len() > 64 {
            return Err(Tpm2SealAuthorityError::InvalidConfiguration);
        }
        let lock = open_private_lock(lock_path)?;
        let mut backend = CommandKeystoreBackend {
            index,
            authorization,
        };
        lock.lock_exclusive().map_err(io_error)?;
        let result = (|| {
            if backend.validate_public(true).is_ok() {
                let record = KeystoreRecord::decode(&backend.read()?, index, binding)?;
                return Ok(record.commitment());
            }

            let previously_defined_unwritten = backend.validate_public(false).is_ok();
            if !previously_defined_unwritten {
                backend.define(&owner_authorization)?;
                backend.validate_public(false)?;
            }
            let record = KeystoreRecord::generate(index, binding)?;
            let encoded = record.encode();
            backend.write(&encoded[..])?;
            backend.validate_public(true)?;
            let stored = KeystoreRecord::decode(&backend.read()?, index, binding)?;
            if stored.commitment() != record.commitment() {
                return Err(Tpm2SealAuthorityError::InvalidRecord);
            }
            Ok(stored.commitment())
        })();
        let unlock = FileExt::unlock(&lock).map_err(io_error);
        result?;
        unlock?;
        let mut keystore = Self {
            index,
            binding,
            lock,
            backend: Box::new(backend),
        };
        keystore.with_lock(|this| this.read_record().map(|_| ()))?;
        Ok(keystore)
    }

    /// Return the non-secret commitment of the exact bound hardware record.
    pub fn record_commitment(&mut self) -> Result<[u8; 32], Tpm2SealAuthorityError> {
        self.with_lock(|this| this.read_record().map(|record| record.commitment()))
    }

    /// Derive the operational snapshot passphrase from both operator knowledge
    /// and the wallet-bound hardware record.
    pub fn operational_passphrase(
        &mut self,
        recovery_password: &WalletPassphrase,
    ) -> Result<WalletPassphrase, Tpm2SealAuthorityError> {
        let record = self.with_lock(|this| this.read_record())?;
        let hkdf = Hkdf::<Sha256>::new(
            Some(&record.secret[..]),
            recovery_password.expose().as_bytes(),
        );
        let mut info = Vec::with_capacity(PASSPHRASE_KDF_INFO.len() + 32);
        info.extend_from_slice(PASSPHRASE_KDF_INFO);
        info.extend_from_slice(&self.binding.as_bytes());
        let mut derived = Zeroizing::new([0u8; 32]);
        hkdf.expand(&info, &mut derived[..])
            .map_err(|_| Tpm2SealAuthorityError::InvalidConfiguration)?;
        WalletPassphrase::new(hex::encode(&derived[..]))
            .map_err(|_| Tpm2SealAuthorityError::InvalidConfiguration)
    }

    /// Derive and create one owner-only temporary operational-password file
    /// without exposing the password through a public accessor.
    pub fn write_operational_passphrase_create_only(
        &mut self,
        recovery_password: &WalletPassphrase,
        path: &Path,
    ) -> Result<(), Tpm2SealAuthorityError> {
        let parent = path
            .parent()
            .ok_or(Tpm2SealAuthorityError::InvalidConfiguration)?;
        let metadata = std::fs::symlink_metadata(parent).map_err(io_error)?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(Tpm2SealAuthorityError::InvalidConfiguration);
        }
        let passphrase = self.operational_passphrase(recovery_password)?;
        dom_wallet_crypto::save_private_bytes_noclobber(path, passphrase.expose().as_bytes())
            .map_err(|error| Tpm2SealAuthorityError::Io(error.to_string()))
    }

    fn with_lock<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Tpm2SealAuthorityError>,
    ) -> Result<T, Tpm2SealAuthorityError> {
        self.lock.lock_exclusive().map_err(io_error)?;
        let result = operation(self);
        let unlock = FileExt::unlock(&self.lock).map_err(io_error);
        result.and_then(|value| unlock.map(|()| value))
    }

    fn read_record(&mut self) -> Result<KeystoreRecord, Tpm2SealAuthorityError> {
        self.backend.validate_public(true)?;
        KeystoreRecord::decode(&self.backend.read()?, self.index, self.binding)
    }
}

impl CommandKeystoreBackend {
    fn public_output(&mut self) -> Result<Vec<u8>, Tpm2SealAuthorityError> {
        let index = format!("0x{:08x}", self.index);
        let arguments = [
            OsString::from("-T"),
            OsString::from(TPM2_DEVICE),
            OsString::from(index),
        ];
        run_command(TPM2_NVREADPUBLIC, &arguments, None)
    }
}

impl KeystoreBackend for CommandKeystoreBackend {
    fn validate_public(&mut self, written: bool) -> Result<(), Tpm2SealAuthorityError> {
        validate_public_output(&self.public_output()?, self.index, RECORD_BYTES, written)
    }

    fn define(&mut self, owner_authorization: &[u8]) -> Result<(), Tpm2SealAuthorityError> {
        let index_auth = SecretMemfd::create(self.authorization.expose())?;
        let owner_auth = SecretMemfd::create(owner_authorization)?;
        let index = format!("0x{:08x}", self.index);
        let arguments = [
            OsString::from("-Q"),
            OsString::from("-T"),
            OsString::from(TPM2_DEVICE),
            OsString::from("-C"),
            OsString::from("o"),
            OsString::from("-P"),
            auth_argument(owner_auth.path()),
            OsString::from("-p"),
            auth_argument(index_auth.path()),
            OsString::from("-s"),
            OsString::from(RECORD_BYTES.to_string()),
            OsString::from("-g"),
            OsString::from("sha256"),
            OsString::from("-a"),
            OsString::from("authread|authwrite"),
            OsString::from(index),
        ];
        run_command(TPM2_NVDEFINE, &arguments, None).map(|_| ())
    }

    fn read(&mut self) -> Result<Zeroizing<Vec<u8>>, Tpm2SealAuthorityError> {
        let auth = SecretMemfd::create(self.authorization.expose())?;
        let index = format!("0x{:08x}", self.index);
        let arguments = [
            OsString::from("-Q"),
            OsString::from("-T"),
            OsString::from(TPM2_DEVICE),
            OsString::from("-C"),
            OsString::from(index.clone()),
            OsString::from("-P"),
            auth_argument(auth.path()),
            OsString::from("-s"),
            OsString::from(RECORD_BYTES.to_string()),
            OsString::from(index),
        ];
        run_command(TPM2_NVREAD, &arguments, None).map(Zeroizing::new)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), Tpm2SealAuthorityError> {
        if bytes.len() != RECORD_BYTES {
            return Err(Tpm2SealAuthorityError::InvalidConfiguration);
        }
        let auth = SecretMemfd::create(self.authorization.expose())?;
        let index = format!("0x{:08x}", self.index);
        let arguments = [
            OsString::from("-Q"),
            OsString::from("-T"),
            OsString::from(TPM2_DEVICE),
            OsString::from("-C"),
            OsString::from(index.clone()),
            OsString::from("-P"),
            auth_argument(auth.path()),
            OsString::from("-i"),
            OsString::from("-"),
            OsString::from(index),
        ];
        run_command(TPM2_NVWRITE, &arguments, Some(bytes)).map(|_| ())
    }
}

fn record_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_HASH_DOMAIN);
    hasher.update(prefix);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, os::unix::fs::PermissionsExt, rc::Rc};

    struct MemoryBackend {
        bytes: Rc<RefCell<Vec<u8>>>,
        written: bool,
    }

    impl KeystoreBackend for MemoryBackend {
        fn validate_public(&mut self, written: bool) -> Result<(), Tpm2SealAuthorityError> {
            if written == self.written {
                Ok(())
            } else {
                Err(Tpm2SealAuthorityError::InvalidRecord)
            }
        }

        fn define(&mut self, _owner_authorization: &[u8]) -> Result<(), Tpm2SealAuthorityError> {
            Ok(())
        }

        fn read(&mut self) -> Result<Zeroizing<Vec<u8>>, Tpm2SealAuthorityError> {
            Ok(Zeroizing::new(self.bytes.borrow().clone()))
        }

        fn write(&mut self, bytes: &[u8]) -> Result<(), Tpm2SealAuthorityError> {
            *self.bytes.borrow_mut() = bytes.to_vec();
            self.written = true;
            Ok(())
        }
    }

    fn test_keystore(secret: [u8; 32]) -> (tempfile::TempDir, Tpm2WalletKeystore) {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let binding = Tpm2AuthorityBinding::from_bytes([0x29; 32]).expect("binding");
        let record = KeystoreRecord {
            index: USDOM_TPM2_KEYSTORE_NV_INDEX,
            binding,
            secret: Zeroizing::new(secret),
        };
        let bytes = Rc::new(RefCell::new(record.encode().to_vec()));
        let lock = open_private_lock(&directory.path().join("keystore.lock")).expect("lock");
        let keystore = Tpm2WalletKeystore {
            index: USDOM_TPM2_KEYSTORE_NV_INDEX,
            binding,
            lock,
            backend: Box::new(MemoryBackend {
                bytes,
                written: true,
            }),
        };
        (directory, keystore)
    }

    #[test]
    fn record_is_canonical_wallet_bound_and_corruption_detected() {
        let binding = Tpm2AuthorityBinding::from_bytes([0x31; 32]).expect("binding");
        let record = KeystoreRecord {
            index: USDOM_TPM2_KEYSTORE_NV_INDEX,
            binding,
            secret: Zeroizing::new([0x41; 32]),
        };
        let encoded = record.encode();
        let decoded = KeystoreRecord::decode(&encoded[..], USDOM_TPM2_KEYSTORE_NV_INDEX, binding)
            .expect("decode");
        assert_eq!(decoded.commitment(), record.commitment());
        for offset in [0usize, 10, 45, 77, RECORD_BYTES - 1] {
            let mut corrupted = *encoded;
            corrupted[offset] ^= 1;
            assert!(
                KeystoreRecord::decode(&corrupted, USDOM_TPM2_KEYSTORE_NV_INDEX, binding).is_err()
            );
        }
    }

    #[test]
    fn operational_passphrase_requires_both_password_and_hardware_secret() {
        let recovery = WalletPassphrase::new("test-only recovery password".into()).expect("pass");
        let (_directory_a, mut a) = test_keystore([0x51; 32]);
        let (_directory_b, mut b) = test_keystore([0x52; 32]);
        let first = a
            .operational_passphrase(&recovery)
            .expect("first operational password");
        let repeated = a
            .operational_passphrase(&recovery)
            .expect("repeated operational password");
        let different_hardware = b
            .operational_passphrase(&recovery)
            .expect("different hardware password");
        assert_eq!(first.expose(), repeated.expose());
        assert_ne!(first.expose(), different_hardware.expose());

        let other_recovery =
            WalletPassphrase::new("different recovery password".into()).expect("pass");
        let different_password = a
            .operational_passphrase(&other_recovery)
            .expect("different recovery password output");
        assert_ne!(first.expose(), different_password.expose());
    }

    #[test]
    fn operational_passphrase_export_is_noclobber_and_preserves_existing_files() {
        let recovery = WalletPassphrase::new("test-only recovery password".into()).expect("pass");
        let (directory, mut keystore) = test_keystore([0x63; 32]);
        let expected = keystore
            .operational_passphrase(&recovery)
            .expect("derive")
            .expose()
            .as_bytes()
            .to_vec();
        let output = directory.path().join("operational-password");
        keystore
            .write_operational_passphrase_create_only(&recovery, &output)
            .expect("write");
        assert_eq!(std::fs::read(&output).expect("read"), expected);
        assert_eq!(
            std::fs::metadata(&output)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );

        let existing = directory.path().join("existing");
        std::fs::write(&existing, b"preserve").expect("existing");
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert!(keystore
            .write_operational_passphrase_create_only(&recovery, &existing)
            .is_err());
        assert_eq!(
            std::fs::read(&existing).expect("read existing"),
            b"preserve"
        );
    }
}
