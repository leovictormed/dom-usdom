//! TPM2 NV-backed rollback-resistant wallet snapshot authority.
//!
//! One ordinary NV index retains the complete two-phase state. Filesystem
//! storage is used only for cross-process serialization and temporary command
//! inputs; it is never accepted as the authoritative seal state.

use std::{
    ffi::OsString,
    fs::File,
    io::{Seek, Write},
    os::unix::{ffi::OsStringExt, io::AsRawFd},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use fs2::FileExt;
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    WalletPassphrase, WalletSealAuthorityError, WalletSealAuthorityState, WalletSnapshotSeal,
    WalletSnapshotSealAuthority, RECIPIENT_ADDRESS_BYTES,
};

const RECORD_MAGIC: &[u8; 8] = b"USWTPM01";
const RECORD_VERSION: u16 = 1;
const RECORD_PREFIX_BYTES: usize = 8 + 2 + 4 + 32 + 1 + 5 + 48 + 48;
const RECORD_BYTES: usize = RECORD_PREFIX_BYTES + 32;
const RECORD_HASH_DOMAIN: &[u8] = b"DOM:usdom-wallet:tpm2-authority-record:v1";
const BINDING_HASH_DOMAIN: &[u8] = b"DOM:usdom-wallet:tpm2-authority-binding:v1";
const CREDENTIAL_ENVELOPE_MAGIC: &[u8; 14] = b"USDOM-TPM-AUTH";
const CREDENTIAL_ENVELOPE_VERSION: u16 = 1;
const CREDENTIAL_MAGIC: &[u8; 8] = b"UDTPMA01";
const CREDENTIAL_BYTES: usize = 8 + 4 + 32 + 32;
const AUTHORIZATION_BYTES: usize = 32;
const TPM2_NV_FIRST: u32 = 0x0100_0000;
const TPM2_NV_LAST: u32 = 0x01ff_ffff;
pub(crate) const TPM2_DEVICE: &str = "device:/dev/tpmrm0";
pub(crate) const TPM2_NVREAD: &str = "/usr/bin/tpm2_nvread";
pub(crate) const TPM2_NVREADPUBLIC: &str = "/usr/bin/tpm2_nvreadpublic";
pub(crate) const TPM2_NVWRITE: &str = "/usr/bin/tpm2_nvwrite";
pub(crate) const TPM2_NVDEFINE: &str = "/usr/bin/tpm2_nvdefine";
const TPM2_ALG_SHA256: u32 = 0x000b;
const TPM2_NV_AUTHWRITE: u32 = 1 << 2;
const TPM2_NV_AUTHREAD: u32 = 1 << 18;
const TPM2_NV_WRITTEN: u32 = 1 << 29;

/// Fixed TPM2 NV handle reserved for the production native-USD wallet seal.
pub const USDOM_TPM2_NV_INDEX: u32 = 0x0155_5344;

/// Exact public identity bound into every TPM authority record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tpm2AuthorityBinding([u8; 32]);

impl Tpm2AuthorityBinding {
    /// Derive the authority identity from the exact public release, native
    /// chain and wallet recipient address.
    pub fn derive(
        network_magic: u32,
        chain_id: [u8; 32],
        manifest_sha256: [u8; 32],
        wallet_address: [u8; RECIPIENT_ADDRESS_BYTES],
    ) -> Result<Self, Tpm2SealAuthorityError> {
        if network_magic == 0
            || chain_id == [0; 32]
            || manifest_sha256 == [0; 32]
            || wallet_address == [0; RECIPIENT_ADDRESS_BYTES]
        {
            return Err(Tpm2SealAuthorityError::InvalidConfiguration);
        }
        let mut hasher = Sha256::new();
        hasher.update(BINDING_HASH_DOMAIN);
        hasher.update(network_magic.to_be_bytes());
        hasher.update(chain_id);
        hasher.update(manifest_sha256);
        hasher.update(wallet_address);
        Self::from_bytes(hasher.finalize().into())
    }

    /// Construct a nonzero binding derived by the caller from the release,
    /// chain and wallet public identity.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Tpm2SealAuthorityError> {
        if bytes == [0; 32] {
            return Err(Tpm2SealAuthorityError::InvalidConfiguration);
        }
        Ok(Self(bytes))
    }

    /// Return the exact public binding bytes.
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Zeroizing 256-bit authorization for one TPM NV index.
pub struct Tpm2NvAuthorization(Zeroizing<[u8; AUTHORIZATION_BYTES]>);

impl Tpm2NvAuthorization {
    /// Import one exact nonzero 256-bit index authorization.
    pub fn new(bytes: [u8; AUTHORIZATION_BYTES]) -> Result<Self, Tpm2SealAuthorityError> {
        if bytes == [0; AUTHORIZATION_BYTES] {
            return Err(Tpm2SealAuthorityError::InvalidConfiguration);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Generate a fresh index authorization and create its encrypted,
    /// create-only recovery envelope.
    pub fn create_encrypted(
        path: &Path,
        index: u32,
        binding: Tpm2AuthorityBinding,
        password: &WalletPassphrase,
    ) -> Result<Self, Tpm2SealAuthorityError> {
        validate_index(index)?;
        let mut authorization = Zeroizing::new([0u8; AUTHORIZATION_BYTES]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut authorization[..])
            .map_err(|_| Tpm2SealAuthorityError::RandomnessUnavailable)?;
        if authorization.iter().all(|byte| *byte == 0) {
            return Err(Tpm2SealAuthorityError::InvalidConfiguration);
        }
        let mut plaintext = Zeroizing::new([0u8; CREDENTIAL_BYTES]);
        plaintext[..8].copy_from_slice(CREDENTIAL_MAGIC);
        plaintext[8..12].copy_from_slice(&index.to_be_bytes());
        plaintext[12..44].copy_from_slice(&binding.0);
        plaintext[44..].copy_from_slice(&authorization[..]);
        dom_wallet_crypto::save_envelope_bytes_noclobber(
            path,
            CREDENTIAL_ENVELOPE_MAGIC,
            CREDENTIAL_ENVELOPE_VERSION,
            &plaintext[..],
            password.expose(),
        )
        .map_err(|error| Tpm2SealAuthorityError::Credential(error.to_string()))?;
        Self::new(*authorization)
    }

    /// Restore the exact index authorization from its authenticated encrypted
    /// envelope and require the caller's index and binding.
    pub fn load_encrypted(
        path: &Path,
        index: u32,
        binding: Tpm2AuthorityBinding,
        password: &WalletPassphrase,
    ) -> Result<Self, Tpm2SealAuthorityError> {
        validate_index(index)?;
        let plaintext = dom_wallet_crypto::load_envelope_bytes(
            path,
            CREDENTIAL_ENVELOPE_MAGIC,
            CREDENTIAL_ENVELOPE_VERSION,
            CREDENTIAL_BYTES,
            password.expose(),
        )
        .map_err(|error| Tpm2SealAuthorityError::Credential(error.to_string()))?;
        Self::from_credential_plaintext(&plaintext, index, binding)
    }

    /// Restore an index authorization from one already captured encrypted
    /// credential. This binds the TPM authorization and external evidence hash
    /// to the same ciphertext bytes.
    pub fn load_encrypted_bytes(
        envelope: &[u8],
        index: u32,
        binding: Tpm2AuthorityBinding,
        password: &WalletPassphrase,
    ) -> Result<Self, Tpm2SealAuthorityError> {
        validate_index(index)?;
        let plaintext = dom_wallet_crypto::decrypt_envelope_bytes(
            envelope,
            CREDENTIAL_ENVELOPE_MAGIC,
            CREDENTIAL_ENVELOPE_VERSION,
            CREDENTIAL_BYTES,
            password.expose(),
        )
        .map_err(|error| Tpm2SealAuthorityError::Credential(error.to_string()))?;
        Self::from_credential_plaintext(&plaintext, index, binding)
    }

    fn from_credential_plaintext(
        plaintext: &[u8],
        index: u32,
        binding: Tpm2AuthorityBinding,
    ) -> Result<Self, Tpm2SealAuthorityError> {
        if plaintext.len() != CREDENTIAL_BYTES
            || &plaintext[..8] != CREDENTIAL_MAGIC
            || u32::from_be_bytes(
                plaintext[8..12]
                    .try_into()
                    .map_err(|_| Tpm2SealAuthorityError::InvalidConfiguration)?,
            ) != index
            || plaintext[12..44] != binding.0
        {
            return Err(Tpm2SealAuthorityError::InvalidConfiguration);
        }
        let bytes: [u8; AUTHORIZATION_BYTES] = plaintext[44..]
            .try_into()
            .map_err(|_| Tpm2SealAuthorityError::InvalidConfiguration)?;
        Self::new(bytes)
    }

    pub(crate) fn expose(&self) -> &[u8; AUTHORIZATION_BYTES] {
        &self.0
    }
}

/// Detailed construction and TPM transport failures.
#[derive(Debug, Error)]
pub enum Tpm2SealAuthorityError {
    /// The operating system CSPRNG failed; no credential was created.
    #[error("operating-system randomness unavailable")]
    RandomnessUnavailable,
    /// Handle, binding, authorization, path or record configuration is invalid.
    #[error("invalid TPM2 wallet seal authority configuration")]
    InvalidConfiguration,
    /// A private lock or temporary authorization file could not be handled.
    #[error("TPM2 wallet seal authority I/O failed: {0}")]
    Io(String),
    /// The encrypted index-authorization credential failed closed.
    #[error("TPM2 wallet seal credential failed: {0}")]
    Credential(String),
    /// An exact TPM2 command failed without exposing authorization material.
    #[error("TPM2 wallet seal authority command failed: {0}")]
    Command(String),
    /// The NV bytes were malformed, noncanonical, corrupt or bound elsewhere.
    #[error("invalid TPM2 wallet seal authority record")]
    InvalidRecord,
    /// The current state does not match the requested compare-and-swap step.
    #[error("TPM2 wallet seal authority compare-and-swap conflict")]
    Conflict,
}

trait NvBackend {
    fn validate_public(&mut self) -> Result<(), Tpm2SealAuthorityError>;
    fn read(&mut self) -> Result<Vec<u8>, Tpm2SealAuthorityError>;
    fn write(&mut self, bytes: &[u8]) -> Result<(), Tpm2SealAuthorityError>;
}

struct CommandNvBackend {
    index: u32,
    authorization: Tpm2NvAuthorization,
}

/// Production TPM-backed implementation of the wallet two-phase authority.
pub struct Tpm2NvSealAuthority {
    index: u32,
    binding: Tpm2AuthorityBinding,
    lock: File,
    backend: Box<dyn NvBackend>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthorityRecord {
    index: u32,
    binding: Tpm2AuthorityBinding,
    state: WalletSealAuthorityState,
}

impl AuthorityRecord {
    fn encode(self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0u8; RECORD_BYTES];
        bytes[..8].copy_from_slice(RECORD_MAGIC);
        bytes[8..10].copy_from_slice(&RECORD_VERSION.to_be_bytes());
        bytes[10..14].copy_from_slice(&self.index.to_be_bytes());
        bytes[14..46].copy_from_slice(&self.binding.0);
        let mut flags = 0u8;
        if self.state.committed.is_some() {
            flags |= 1;
        }
        if self.state.prepared.is_some() {
            flags |= 2;
        }
        bytes[46] = flags;
        if let Some(seal) = self.state.committed {
            bytes[52..100].copy_from_slice(&seal.to_bytes());
        }
        if let Some(seal) = self.state.prepared {
            bytes[100..148].copy_from_slice(&seal.to_bytes());
        }
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
            || bytes[14..46] != expected_binding.0
            || bytes[47..52] != [0; 5]
            || bytes[46] & !3 != 0
            || bytes[RECORD_PREFIX_BYTES..] != record_digest(&bytes[..RECORD_PREFIX_BYTES])
        {
            return Err(Tpm2SealAuthorityError::InvalidRecord);
        }
        let flags = bytes[46];
        let committed = decode_optional_seal(flags & 1 != 0, &bytes[52..100])?;
        let prepared = decode_optional_seal(flags & 2 != 0, &bytes[100..148])?;
        validate_authority_state(WalletSealAuthorityState {
            committed,
            prepared,
        })?;
        let record = Self {
            index: expected_index,
            binding: expected_binding,
            state: WalletSealAuthorityState {
                committed,
                prepared,
            },
        };
        if record.encode().as_slice() != bytes {
            return Err(Tpm2SealAuthorityError::InvalidRecord);
        }
        Ok(record)
    }
}

impl Tpm2NvSealAuthority {
    /// Open an existing authority and require one valid, wallet-bound NV
    /// record before returning.
    pub fn open(
        index: u32,
        binding: Tpm2AuthorityBinding,
        authorization: Tpm2NvAuthorization,
        lock_path: &Path,
    ) -> Result<Self, Tpm2SealAuthorityError> {
        validate_index(index)?;
        let lock = open_private_lock(lock_path)?;
        let mut authority = Self {
            index,
            binding,
            lock,
            backend: Box::new(CommandNvBackend {
                index,
                authorization,
            }),
        };
        authority.with_lock(|this| this.read_record().map(|_| ()))?;
        Ok(authority)
    }

    /// Define and initialize the fixed NV index, or verify an idempotent retry
    /// after a crash. The owner authorization is used only for `NV_DefineSpace`.
    pub fn initialize(
        index: u32,
        binding: Tpm2AuthorityBinding,
        authorization: Tpm2NvAuthorization,
        owner_authorization: Zeroizing<Vec<u8>>,
        initial_committed: WalletSnapshotSeal,
        lock_path: &Path,
    ) -> Result<Self, Tpm2SealAuthorityError> {
        validate_index(index)?;
        if owner_authorization.len() > 64 {
            return Err(Tpm2SealAuthorityError::InvalidConfiguration);
        }
        let lock = open_private_lock(lock_path)?;
        let mut backend = CommandNvBackend {
            index,
            authorization,
        };
        let expected = AuthorityRecord {
            index,
            binding,
            state: WalletSealAuthorityState {
                committed: Some(initial_committed),
                prepared: None,
            },
        };
        let mut authority = Self {
            index,
            binding,
            lock,
            backend: Box::new(EmptyBackend),
        };
        authority.lock.lock_exclusive().map_err(io_error)?;
        let result = (|| {
            match backend.read() {
                Ok(bytes) => {
                    let current = AuthorityRecord::decode(&bytes, index, binding)?;
                    if current != expected {
                        return Err(Tpm2SealAuthorityError::Conflict);
                    }
                }
                Err(_) => {
                    // If define fails, a prior run may have defined the index
                    // but crashed before its first write. The random index
                    // authorization makes the following write succeed only for
                    // that exact partial initialization; unrelated occupied
                    // handles stay closed.
                    let _define_result = backend.define(&owner_authorization);
                    backend.write(&expected.encode())?;
                    let stored = backend.read()?;
                    if AuthorityRecord::decode(&stored, index, binding)? != expected {
                        return Err(Tpm2SealAuthorityError::InvalidRecord);
                    }
                }
            }
            backend.validate_public()?;
            Ok(())
        })();
        let unlock = FileExt::unlock(&authority.lock).map_err(io_error);
        result?;
        unlock?;
        authority.backend = Box::new(backend);
        Ok(authority)
    }

    /// Return the exact binding checked by this authority instance.
    pub const fn binding(&self) -> Tpm2AuthorityBinding {
        self.binding
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

    fn read_record(&mut self) -> Result<AuthorityRecord, Tpm2SealAuthorityError> {
        // Revalidate the public area for every authoritative read. Opening the
        // index once is insufficient: the TPM owner hierarchy can undefine and
        // recreate an ordinary NV index while a long-lived operator process is
        // running. The record binding still authenticates the contents, while
        // this check also requires the exact hash algorithm, attributes and
        // size inside the same local critical section as the state operation.
        self.backend.validate_public()?;
        AuthorityRecord::decode(&self.backend.read()?, self.index, self.binding)
    }

    fn replace_state(
        &mut self,
        expected: WalletSealAuthorityState,
        next: WalletSealAuthorityState,
    ) -> Result<(), Tpm2SealAuthorityError> {
        validate_authority_state(next)?;
        self.with_lock(|this| {
            let current = this.read_record()?;
            if current.state != expected {
                return Err(Tpm2SealAuthorityError::Conflict);
            }
            let proposed = AuthorityRecord {
                index: this.index,
                binding: this.binding,
                state: next,
            };
            this.backend.write(&proposed.encode())?;
            if this.read_record()? != proposed {
                return Err(Tpm2SealAuthorityError::InvalidRecord);
            }
            Ok(())
        })
    }
}

impl WalletSnapshotSealAuthority for Tpm2NvSealAuthority {
    fn state(&mut self) -> Result<WalletSealAuthorityState, WalletSealAuthorityError> {
        self.with_lock(|this| this.read_record().map(|record| record.state))
            .map_err(map_authority_error)
    }

    fn prepare(
        &mut self,
        expected: Option<WalletSnapshotSeal>,
        proposed: WalletSnapshotSeal,
    ) -> Result<(), WalletSealAuthorityError> {
        self.replace_state(
            WalletSealAuthorityState {
                committed: expected,
                prepared: None,
            },
            WalletSealAuthorityState {
                committed: expected,
                prepared: Some(proposed),
            },
        )
        .map_err(map_authority_error)
    }

    fn commit(&mut self, proposed: WalletSnapshotSeal) -> Result<(), WalletSealAuthorityError> {
        let current = self.state()?;
        if current.prepared != Some(proposed) {
            return Err(WalletSealAuthorityError::Conflict);
        }
        self.replace_state(
            current,
            WalletSealAuthorityState {
                committed: Some(proposed),
                prepared: None,
            },
        )
        .map_err(map_authority_error)
    }

    fn abort(&mut self, proposed: WalletSnapshotSeal) -> Result<(), WalletSealAuthorityError> {
        let current = self.state()?;
        if current.prepared != Some(proposed) {
            return Err(WalletSealAuthorityError::Conflict);
        }
        self.replace_state(
            current,
            WalletSealAuthorityState {
                committed: current.committed,
                prepared: None,
            },
        )
        .map_err(map_authority_error)
    }
}

impl CommandNvBackend {
    fn define(&mut self, owner_authorization: &[u8]) -> Result<(), Tpm2SealAuthorityError> {
        let index_auth = SecretMemfd::create(&self.authorization.0[..])?;
        let owner_auth = SecretMemfd::create(owner_authorization)?;
        let index = format!("0x{:08x}", self.index);
        let args = [
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
        run_command(TPM2_NVDEFINE, &args, None).map(|_| ())
    }

    fn authorization_argument(&self, file: &SecretMemfd) -> OsString {
        auth_argument(file.path())
    }
}

impl NvBackend for CommandNvBackend {
    fn validate_public(&mut self) -> Result<(), Tpm2SealAuthorityError> {
        let index = format!("0x{:08x}", self.index);
        let args = [
            OsString::from("-T"),
            OsString::from(TPM2_DEVICE),
            OsString::from(index),
        ];
        let output = run_command(TPM2_NVREADPUBLIC, &args, None)?;
        validate_public_output(&output, self.index, RECORD_BYTES, true)
    }

    fn read(&mut self) -> Result<Vec<u8>, Tpm2SealAuthorityError> {
        let auth = SecretMemfd::create(&self.authorization.0[..])?;
        let index = format!("0x{:08x}", self.index);
        let args = [
            OsString::from("-Q"),
            OsString::from("-T"),
            OsString::from(TPM2_DEVICE),
            OsString::from("-C"),
            OsString::from(index.clone()),
            OsString::from("-P"),
            self.authorization_argument(&auth),
            OsString::from("-s"),
            OsString::from(RECORD_BYTES.to_string()),
            OsString::from(index),
        ];
        run_command(TPM2_NVREAD, &args, None)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), Tpm2SealAuthorityError> {
        if bytes.len() != RECORD_BYTES {
            return Err(Tpm2SealAuthorityError::InvalidConfiguration);
        }
        let auth = SecretMemfd::create(&self.authorization.0[..])?;
        let index = format!("0x{:08x}", self.index);
        let args = [
            OsString::from("-Q"),
            OsString::from("-T"),
            OsString::from(TPM2_DEVICE),
            OsString::from("-C"),
            OsString::from(index.clone()),
            OsString::from("-P"),
            self.authorization_argument(&auth),
            OsString::from("-i"),
            OsString::from("-"),
            OsString::from(index),
        ];
        run_command(TPM2_NVWRITE, &args, Some(bytes)).map(|_| ())
    }
}

struct EmptyBackend;

impl NvBackend for EmptyBackend {
    fn validate_public(&mut self) -> Result<(), Tpm2SealAuthorityError> {
        Err(Tpm2SealAuthorityError::InvalidConfiguration)
    }

    fn read(&mut self) -> Result<Vec<u8>, Tpm2SealAuthorityError> {
        Err(Tpm2SealAuthorityError::InvalidConfiguration)
    }

    fn write(&mut self, _bytes: &[u8]) -> Result<(), Tpm2SealAuthorityError> {
        Err(Tpm2SealAuthorityError::InvalidConfiguration)
    }
}

pub(crate) struct SecretMemfd {
    _file: File,
    path: PathBuf,
}

impl SecretMemfd {
    pub(crate) fn create(secret: &[u8]) -> Result<Self, Tpm2SealAuthorityError> {
        let fd = rustix::fs::memfd_create("usdom-tpm-auth", rustix::fs::MemfdFlags::empty())
            .map_err(|error| Tpm2SealAuthorityError::Io(error.to_string()))?;
        let mut file = File::from(fd);
        file.write_all(secret).map_err(io_error)?;
        file.rewind().map_err(io_error)?;
        let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        Ok(Self { _file: file, path })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn run_command(
    program: &str,
    arguments: &[OsString],
    stdin: Option<&[u8]>,
) -> Result<Vec<u8>, Tpm2SealAuthorityError> {
    if std::fs::symlink_metadata(program)
        .map(|metadata| !metadata.file_type().is_file() || metadata.file_type().is_symlink())
        .unwrap_or(true)
    {
        return Err(Tpm2SealAuthorityError::Command(format!(
            "required tool is unavailable: {program}"
        )));
    }
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = command
        .spawn()
        .map_err(|error| Tpm2SealAuthorityError::Command(error.to_string()))?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .ok_or_else(|| Tpm2SealAuthorityError::Command("missing TPM command stdin".into()))?
            .write_all(input)
            .map_err(|error| Tpm2SealAuthorityError::Command(error.to_string()))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| Tpm2SealAuthorityError::Command(error.to_string()))?;
    if !output.status.success() {
        let mut message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        message.truncate(512);
        if message.is_empty() {
            message = format!("{program} exited with {}", output.status);
        }
        return Err(Tpm2SealAuthorityError::Command(message));
    }
    Ok(output.stdout)
}

pub(crate) fn open_private_lock(path: &Path) -> Result<File, Tpm2SealAuthorityError> {
    dom_wallet_crypto::open_private_lock_file(path)
        .map_err(|error| Tpm2SealAuthorityError::Io(error.to_string()))
}

fn validate_authority_state(state: WalletSealAuthorityState) -> Result<(), Tpm2SealAuthorityError> {
    for seal in [state.committed, state.prepared].into_iter().flatten() {
        WalletSnapshotSeal::from_bytes(&seal.to_bytes())
            .map_err(|_| Tpm2SealAuthorityError::InvalidRecord)?;
    }
    if let Some(prepared) = state.prepared {
        let expected_generation = state
            .committed
            .map_or(Some(1), |committed| committed.generation.checked_add(1));
        if expected_generation != Some(prepared.generation) {
            return Err(Tpm2SealAuthorityError::InvalidRecord);
        }
    }
    Ok(())
}

fn decode_optional_seal(
    present: bool,
    bytes: &[u8],
) -> Result<Option<WalletSnapshotSeal>, Tpm2SealAuthorityError> {
    if present {
        WalletSnapshotSeal::from_bytes(bytes)
            .map(Some)
            .map_err(|_| Tpm2SealAuthorityError::InvalidRecord)
    } else if bytes.iter().all(|byte| *byte == 0) {
        Ok(None)
    } else {
        Err(Tpm2SealAuthorityError::InvalidRecord)
    }
}

fn record_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_HASH_DOMAIN);
    hasher.update(prefix);
    hasher.finalize().into()
}

pub(crate) fn validate_index(index: u32) -> Result<(), Tpm2SealAuthorityError> {
    if !(TPM2_NV_FIRST..=TPM2_NV_LAST).contains(&index) {
        return Err(Tpm2SealAuthorityError::InvalidConfiguration);
    }
    Ok(())
}

pub(crate) fn validate_public_output(
    output: &[u8],
    expected_index: u32,
    expected_size: usize,
    expected_written: bool,
) -> Result<(), Tpm2SealAuthorityError> {
    let text = std::str::from_utf8(output).map_err(|_| Tpm2SealAuthorityError::InvalidRecord)?;
    let mut target = false;
    let mut found = false;
    let mut group = "";
    let mut hash_algorithm = None;
    let mut attributes = None;
    let mut size = None;
    let mut empty_policy = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.starts_with('\t') {
            if target {
                break;
            }
            let Some(raw_handle) = line.strip_suffix(':') else {
                continue;
            };
            let parsed = raw_handle
                .strip_prefix("0x")
                .and_then(|value| u32::from_str_radix(value, 16).ok());
            target = parsed == Some(expected_index);
            found |= target;
            group = "";
            continue;
        }
        if !target {
            continue;
        }
        let trimmed = line.trim();
        match trimmed {
            "hash algorithm:" => group = "hash",
            "attributes:" => group = "attributes",
            _ => {
                if let Some(value) = trimmed.strip_prefix("size:") {
                    size = value.trim().parse::<usize>().ok();
                    group = "";
                } else if let Some(value) = trimmed.strip_prefix("authorization policy:") {
                    empty_policy = value.trim().is_empty();
                    group = "";
                } else if let Some(value) = trimmed.strip_prefix("value:") {
                    let parsed = value
                        .trim()
                        .strip_prefix("0x")
                        .and_then(|hex| u32::from_str_radix(hex, 16).ok());
                    match group {
                        "hash" => hash_algorithm = parsed,
                        "attributes" => attributes = parsed,
                        _ => {}
                    }
                }
            }
        }
    }
    let expected_attributes =
        TPM2_NV_AUTHWRITE | TPM2_NV_AUTHREAD | if expected_written { TPM2_NV_WRITTEN } else { 0 };
    if !found
        || hash_algorithm != Some(TPM2_ALG_SHA256)
        || attributes != Some(expected_attributes)
        || size != Some(expected_size)
        || !empty_policy
    {
        return Err(Tpm2SealAuthorityError::InvalidRecord);
    }
    Ok(())
}

pub(crate) fn auth_argument(path: &Path) -> OsString {
    let mut bytes = b"file:".to_vec();
    bytes.extend_from_slice(path.as_os_str().as_encoded_bytes());
    OsString::from_vec(bytes)
}

fn map_authority_error(error: Tpm2SealAuthorityError) -> WalletSealAuthorityError {
    match error {
        Tpm2SealAuthorityError::Conflict => WalletSealAuthorityError::Conflict,
        Tpm2SealAuthorityError::InvalidConfiguration | Tpm2SealAuthorityError::InvalidRecord => {
            WalletSealAuthorityError::InvalidState
        }
        Tpm2SealAuthorityError::Io(_)
        | Tpm2SealAuthorityError::Credential(_)
        | Tpm2SealAuthorityError::Command(_) => WalletSealAuthorityError::Unavailable,
    }
}

pub(crate) fn io_error(error: std::io::Error) -> Tpm2SealAuthorityError {
    Tpm2SealAuthorityError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::{cell::RefCell, rc::Rc};

    #[derive(Clone)]
    struct MemoryBackend(Rc<RefCell<Vec<u8>>>);

    impl NvBackend for MemoryBackend {
        fn validate_public(&mut self) -> Result<(), Tpm2SealAuthorityError> {
            Ok(())
        }

        fn read(&mut self) -> Result<Vec<u8>, Tpm2SealAuthorityError> {
            Ok(self.0.borrow().clone())
        }

        fn write(&mut self, bytes: &[u8]) -> Result<(), Tpm2SealAuthorityError> {
            *self.0.borrow_mut() = bytes.to_vec();
            Ok(())
        }
    }

    fn seal(generation: u64, byte: u8) -> WalletSnapshotSeal {
        WalletSnapshotSeal {
            generation,
            digest: dom_core::Hash256::from_bytes([byte; 32]),
        }
    }

    fn authority() -> (tempfile::TempDir, Tpm2NvSealAuthority, Rc<RefCell<Vec<u8>>>) {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let binding = Tpm2AuthorityBinding::from_bytes([0x42; 32]).expect("binding");
        let record = AuthorityRecord {
            index: USDOM_TPM2_NV_INDEX,
            binding,
            state: WalletSealAuthorityState {
                committed: Some(seal(3, 3)),
                prepared: None,
            },
        };
        let storage = Rc::new(RefCell::new(record.encode().to_vec()));
        let lock = open_private_lock(&directory.path().join("authority.lock")).expect("lock");
        let authority = Tpm2NvSealAuthority {
            index: USDOM_TPM2_NV_INDEX,
            binding,
            lock,
            backend: Box::new(MemoryBackend(Rc::clone(&storage))),
        };
        (directory, authority, storage)
    }

    #[test]
    fn captured_encrypted_credential_restores_the_exact_authorization() {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let path = directory.path().join("credential.usdom");
        let binding = Tpm2AuthorityBinding::from_bytes([0x73; 32]).expect("binding");
        let password =
            WalletPassphrase::new("correct TPM credential password".into()).expect("password");
        let created =
            Tpm2NvAuthorization::create_encrypted(&path, USDOM_TPM2_NV_INDEX, binding, &password)
                .expect("create");
        let encrypted = std::fs::read(&path).expect("read");
        let captured = Tpm2NvAuthorization::load_encrypted_bytes(
            &encrypted,
            USDOM_TPM2_NV_INDEX,
            binding,
            &password,
        )
        .expect("captured restore");
        assert_eq!(created.expose(), captured.expose());
        let wrong_binding = Tpm2AuthorityBinding::from_bytes([0x74; 32]).expect("binding");
        assert!(matches!(
            Tpm2NvAuthorization::load_encrypted_bytes(
                &encrypted,
                USDOM_TPM2_NV_INDEX,
                wrong_binding,
                &password,
            ),
            Err(Tpm2SealAuthorityError::InvalidConfiguration)
        ));
        let mut corrupted = encrypted;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        assert!(matches!(
            Tpm2NvAuthorization::load_encrypted_bytes(
                &corrupted,
                USDOM_TPM2_NV_INDEX,
                binding,
                &password,
            ),
            Err(Tpm2SealAuthorityError::Credential(_))
        ));
    }

    #[test]
    fn canonical_record_rejects_corruption_and_impossible_generations() {
        let binding = Tpm2AuthorityBinding::from_bytes([0x31; 32]).expect("binding");
        let record = AuthorityRecord {
            index: USDOM_TPM2_NV_INDEX,
            binding,
            state: WalletSealAuthorityState {
                committed: Some(seal(8, 8)),
                prepared: Some(seal(9, 9)),
            },
        };
        let bytes = record.encode();
        assert_eq!(
            AuthorityRecord::decode(&bytes, USDOM_TPM2_NV_INDEX, binding).expect("decode"),
            record
        );
        for offset in [0usize, 46, 47, 99, RECORD_BYTES - 1] {
            let mut corrupted = bytes;
            corrupted[offset] ^= 1;
            assert!(AuthorityRecord::decode(&corrupted, USDOM_TPM2_NV_INDEX, binding).is_err());
        }
        let impossible = AuthorityRecord {
            state: WalletSealAuthorityState {
                committed: Some(seal(8, 8)),
                prepared: Some(seal(10, 10)),
            },
            ..record
        }
        .encode();
        assert!(AuthorityRecord::decode(&impossible, USDOM_TPM2_NV_INDEX, binding).is_err());
    }

    #[test]
    fn public_index_metadata_must_match_exact_production_attributes() {
        let valid = format!(
            "0x01000001:\n  hash algorithm:\n    friendly: sha256\n    value: 0xB\n  attributes:\n    friendly: authwrite|authread\n    value: 0x40004\n  size: 4\n  authorization policy:\n\n0x{:x}:\n  name: 000b00\n  hash algorithm:\n    friendly: sha256\n    value: 0xB\n  attributes:\n    friendly: authwrite|authread|written\n    value: 0x20040004\n  size: {}\n  authorization policy:\n",
            USDOM_TPM2_NV_INDEX, RECORD_BYTES
        );
        assert!(
            validate_public_output(valid.as_bytes(), USDOM_TPM2_NV_INDEX, RECORD_BYTES, true,)
                .is_ok()
        );
        for changed in [
            valid.replace("value: 0x20040004", "value: 0x20060004"),
            valid.replace(&format!("size: {RECORD_BYTES}"), "size: 32"),
            valid.replace(
                "authorization policy:\n",
                "authorization policy: deadbeef\n",
            ),
        ] {
            assert!(validate_public_output(
                changed.as_bytes(),
                USDOM_TPM2_NV_INDEX,
                RECORD_BYTES,
                true,
            )
            .is_err());
        }
    }

    #[test]
    fn anonymous_authorization_file_is_inherited_without_filesystem_persistence() {
        let secret = SecretMemfd::create(b"test-only-authority-secret").expect("memfd");
        let output = run_command(
            "/usr/bin/cat",
            &[secret.path().as_os_str().to_owned()],
            None,
        )
        .expect("child reads inherited memfd");
        assert_eq!(output, b"test-only-authority-secret");
        assert!(secret.path().starts_with("/proc/self/fd"));
    }

    #[test]
    fn two_phase_cas_is_exact_and_durable_in_backend() {
        let (_directory, mut authority, storage) = authority();
        let previous = seal(3, 3);
        let next = seal(4, 4);
        authority.prepare(Some(previous), next).expect("prepare");
        assert_eq!(
            authority.state().expect("prepared state"),
            WalletSealAuthorityState {
                committed: Some(previous),
                prepared: Some(next)
            }
        );
        assert_eq!(
            authority.prepare(Some(previous), next),
            Err(WalletSealAuthorityError::Conflict)
        );
        authority.commit(next).expect("commit");
        assert_eq!(
            authority.state().expect("committed state"),
            WalletSealAuthorityState {
                committed: Some(next),
                prepared: None
            }
        );
        assert_eq!(storage.borrow().len(), RECORD_BYTES);
    }

    #[test]
    fn abort_keeps_exact_committed_predecessor() {
        let (_directory, mut authority, _storage) = authority();
        let previous = seal(3, 3);
        let next = seal(4, 4);
        authority.prepare(Some(previous), next).expect("prepare");
        authority.abort(next).expect("abort");
        assert_eq!(
            authority.state().expect("state"),
            WalletSealAuthorityState {
                committed: Some(previous),
                prepared: None
            }
        );
        assert_eq!(
            authority.abort(next),
            Err(WalletSealAuthorityError::Conflict)
        );
    }
}
