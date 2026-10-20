//! Create or verify one encrypted native USDOM recovery backup.
//!
//! Secret material never appears in argv, the environment or stdout. The
//! passphrase is read from one owner-only file and moved into a zeroizing
//! wrapper. Creation is no-clobber and verifies a complete restore before
//! reporting the public recipient address.

use std::{
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
};

use dom_usdom_privacy::{chain_scalar, privacy_policy_hash};
use dom_usdom_wallet::{
    RecipientAddress, WalletPassphrase, WalletRecoverySeed, WalletSecrets,
    MAX_WALLET_PASSPHRASE_BYTES, MIN_WALLET_PASSPHRASE_BYTES, RECIPIENT_ADDRESS_BYTES,
};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

enum Action {
    Help,
    Run(Box<Arguments>),
}

#[derive(Clone, Copy)]
enum Command {
    Create,
    Verify,
}

#[derive(Clone)]
struct Arguments {
    command: Command,
    backup_file: PathBuf,
    password_file: PathBuf,
    dom_domain: [u8; 32],
    expected_privacy_policy_hash: [u8; 32],
    expected_address: Option<[u8; RECIPIENT_ADDRESS_BYTES]>,
}

#[derive(Debug, PartialEq, Eq)]
struct PublicSummary {
    dom_domain: [u8; 32],
    privacy_policy_hash: [u8; 32],
    chain: [u8; 32],
    recipient_address: Vec<u8>,
}

fn main() -> anyhow::Result<()> {
    match parse_arguments(std::env::args_os())? {
        Action::Help => {
            print_help();
            Ok(())
        }
        Action::Run(arguments) => {
            let summary = execute(*arguments)?;
            println!("status: valid");
            println!("dom_domain: {}", hex::encode(summary.dom_domain));
            println!(
                "privacy_policy_hash: {}",
                hex::encode(summary.privacy_policy_hash)
            );
            println!("chain_scalar: {}", hex::encode(summary.chain));
            println!(
                "recipient_address: {}",
                hex::encode(summary.recipient_address)
            );
            Ok(())
        }
    }
}

fn execute(arguments: Arguments) -> anyhow::Result<PublicSummary> {
    let policy = *privacy_policy_hash().as_bytes();
    if arguments.expected_privacy_policy_hash != policy {
        anyhow::bail!("compiled privacy policy does not match the expected manifest policy");
    }
    let chain = chain_scalar(arguments.dom_domain, policy);
    if chain.is_zero() {
        anyhow::bail!("derived USDOM chain identity is invalid");
    }
    if let Some(expected) = arguments.expected_address {
        let expected = RecipientAddress::from_bytes(&expected)?;
        if expected.chain() != chain {
            anyhow::bail!("expected recipient address belongs to another USDOM chain");
        }
    }
    let passphrase = load_passphrase_file(&arguments.password_file)?;
    let wallet = match arguments.command {
        Command::Create => {
            let seed = WalletRecoverySeed::generate(&mut OsRng);
            let created = WalletSecrets::from_recovery_seed(chain, &seed)?;
            let created_address = created.address()?.to_bytes();
            seed.save_encrypted_backup(chain, &arguments.backup_file, &passphrase)?;
            let restored = WalletRecoverySeed::load_encrypted_backup(
                &arguments.backup_file,
                chain,
                &passphrase,
            )?;
            let wallet = WalletSecrets::from_recovery_seed(chain, &restored)?;
            if wallet.address()?.to_bytes() != created_address {
                anyhow::bail!("recovery backup verification changed the recipient address");
            }
            wallet
        }
        Command::Verify => {
            let seed = WalletRecoverySeed::load_encrypted_backup(
                &arguments.backup_file,
                chain,
                &passphrase,
            )?;
            WalletSecrets::from_recovery_seed(chain, &seed)?
        }
    };
    let recipient_address = wallet.address()?.to_bytes();
    if arguments
        .expected_address
        .is_some_and(|expected| expected != recipient_address)
    {
        anyhow::bail!("restored recipient address does not match the expected address");
    }
    Ok(PublicSummary {
        dom_domain: arguments.dom_domain,
        privacy_policy_hash: policy,
        chain: chain.to_bytes(),
        recipient_address: recipient_address.to_vec(),
    })
}

fn load_passphrase_file(path: &Path) -> anyhow::Result<WalletPassphrase> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("password file must have a parent directory"))?;
    let parent_named = std::fs::symlink_metadata(parent)
        .map_err(|error| anyhow::anyhow!("cannot inspect password directory: {error}"))?;
    let named = std::fs::symlink_metadata(path)
        .map_err(|error| anyhow::anyhow!("cannot inspect password file: {error}"))?;
    if !parent_named.file_type().is_dir()
        || parent_named.file_type().is_symlink()
        || !named.file_type().is_file()
        || named.file_type().is_symlink()
    {
        anyhow::bail!("password authority must use regular non-symlink paths");
    }
    let file = std::fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("cannot open password file: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| anyhow::anyhow!("cannot inspect opened password file: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = rustix::process::geteuid().as_raw();
        if parent_named.uid() != owner
            || parent_named.mode() & 0o7777 != 0o700
            || named.uid() != owner
            || opened.uid() != owner
            || named.mode() & 0o7777 != 0o600
            || opened.mode() & 0o7777 != 0o600
            || named.nlink() != 1
            || opened.nlink() != 1
            || named.dev() != opened.dev()
            || named.ino() != opened.ino()
        {
            anyhow::bail!("password file must be an owner-only 0600 file in a 0700 directory");
        }
    }
    let maximum = u64::try_from(MAX_WALLET_PASSPHRASE_BYTES)?;
    if opened.len() == 0 || opened.len() > maximum + 2 {
        anyhow::bail!("password file exceeds the bounded length");
    }
    let mut raw = Zeroizing::new(String::new());
    file.take(maximum + 3)
        .read_to_string(&mut raw)
        .map_err(|error| anyhow::anyhow!("cannot read UTF-8 password file: {error}"))?;
    if raw.len() as u64 > maximum + 2 {
        anyhow::bail!("password file exceeds the bounded length");
    }
    let trimmed = raw
        .strip_suffix("\r\n")
        .or_else(|| raw.strip_suffix('\n'))
        .unwrap_or(&raw);
    if trimmed.len() < MIN_WALLET_PASSPHRASE_BYTES
        || trimmed.len() > MAX_WALLET_PASSPHRASE_BYTES
        || trimmed.chars().any(|character| character.is_control())
    {
        anyhow::bail!("password file contains an invalid passphrase");
    }
    WalletPassphrase::new(trimmed.to_owned()).map_err(Into::into)
}

fn parse_arguments(arguments: impl IntoIterator<Item = OsString>) -> anyhow::Result<Action> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        anyhow::bail!("create, verify, or --help is required")
    };
    if matches!(command.to_str(), Some("-h" | "--help")) {
        if arguments.next().is_some() {
            anyhow::bail!("--help accepts no additional arguments");
        }
        return Ok(Action::Help);
    }
    let command = match command.to_str() {
        Some("create") => Command::Create,
        Some("verify") => Command::Verify,
        _ => anyhow::bail!("first argument must be create, verify, or --help"),
    };
    let remaining: Vec<OsString> = arguments.collect();
    let (pairs, remainder) = remaining.as_chunks::<2>();
    if !remainder.is_empty() {
        anyhow::bail!("every option requires exactly one value");
    }
    let mut backup_file = None;
    let mut password_file = None;
    let mut dom_domain = None;
    let mut expected_privacy_policy_hash = None;
    let mut expected_address = None;
    for pair in pairs {
        let flag = &pair[0];
        let value = &pair[1];
        match flag.to_str() {
            Some("--backup-file") if backup_file.is_none() => {
                backup_file = Some(PathBuf::from(value))
            }
            Some("--password-file") if password_file.is_none() => {
                password_file = Some(PathBuf::from(value))
            }
            Some("--dom-domain") if dom_domain.is_none() => {
                dom_domain = Some(parse_lower_hex_array::<32>(value, "DOM domain")?)
            }
            Some("--privacy-policy-hash") if expected_privacy_policy_hash.is_none() => {
                expected_privacy_policy_hash =
                    Some(parse_lower_hex_array::<32>(value, "privacy policy hash")?)
            }
            Some("--expected-address") if expected_address.is_none() => {
                expected_address = Some(parse_lower_hex_array::<RECIPIENT_ADDRESS_BYTES>(
                    value,
                    "expected recipient address",
                )?)
            }
            Some(
                "--backup-file"
                | "--password-file"
                | "--dom-domain"
                | "--privacy-policy-hash"
                | "--expected-address",
            ) => {
                anyhow::bail!("duplicate argument {flag:?}")
            }
            _ => anyhow::bail!("unknown argument {flag:?}"),
        }
    }
    if matches!(command, Command::Create) && expected_address.is_some() {
        anyhow::bail!("--expected-address is valid only with verify");
    }
    if matches!(command, Command::Verify) && expected_address.is_none() {
        anyhow::bail!("--expected-address is required with verify");
    }
    Ok(Action::Run(Box::new(Arguments {
        command,
        backup_file: backup_file.ok_or_else(|| anyhow::anyhow!("--backup-file is required"))?,
        password_file: password_file
            .ok_or_else(|| anyhow::anyhow!("--password-file is required"))?,
        dom_domain: dom_domain.ok_or_else(|| anyhow::anyhow!("--dom-domain is required"))?,
        expected_privacy_policy_hash: expected_privacy_policy_hash
            .ok_or_else(|| anyhow::anyhow!("--privacy-policy-hash is required"))?,
        expected_address,
    })))
}

fn parse_lower_hex_array<const N: usize>(value: &OsString, label: &str) -> anyhow::Result<[u8; N]> {
    let value = value
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("{label} is not valid UTF-8"))?;
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("{label} must be exact lowercase hexadecimal");
    }
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} has the wrong length"))
}

fn print_help() {
    println!(
        "Create or verify an encrypted native USDOM wallet recovery backup.\n\nUsage:\n  dom-usdom-wallet-recovery create --backup-file PATH --password-file OWNER_ONLY_FILE --dom-domain 64_HEX --privacy-policy-hash 64_HEX\n  dom-usdom-wallet-recovery verify --backup-file PATH --password-file OWNER_ONLY_FILE --dom-domain 64_HEX --privacy-policy-hash 64_HEX --expected-address ADDRESS_HEX\n\nSecret seed and password bytes are never printed or accepted through argv/environment."
    );
}

#[cfg(test)]
mod tests {
    use super::{execute, load_passphrase_file, parse_arguments, Action};
    use dom_usdom_privacy::privacy_policy_hash;
    use std::{ffi::OsString, path::PathBuf};

    fn args(values: &[&str]) -> Vec<OsString> {
        std::iter::once("dom-usdom-wallet-recovery")
            .chain(values.iter().copied())
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn parser_accepts_complete_create_and_rejects_ambiguous_input() {
        let domain = "11".repeat(32);
        let policy = hex::encode(privacy_policy_hash().as_bytes());
        let action = parse_arguments(args(&[
            "create",
            "--backup-file",
            "/tmp/recovery",
            "--password-file",
            "/tmp/password",
            "--dom-domain",
            &domain,
            "--privacy-policy-hash",
            &policy,
        ]))
        .unwrap();
        let Action::Run(arguments) = action else {
            panic!("expected run action")
        };
        assert_eq!(arguments.backup_file, PathBuf::from("/tmp/recovery"));
        assert_eq!(arguments.dom_domain, [0x11; 32]);
        assert!(parse_arguments(args(&["create", "--dom-domain", &domain])).is_err());
        assert!(parse_arguments(args(&[
            "verify",
            "--backup-file",
            "a",
            "--password-file",
            "p",
            "--dom-domain",
            &domain,
            "--privacy-policy-hash",
            &policy,
        ]))
        .is_err());
        assert!(parse_arguments(args(&[
            "create",
            "--backup-file",
            "a",
            "--password-file",
            "p",
            "--dom-domain",
            &domain,
            "--privacy-policy-hash",
            &policy,
            "--expected-address",
            &"00".repeat(104),
        ]))
        .is_err());
        assert!(parse_arguments(args(&[
            "create",
            "--backup-file",
            "a",
            "--backup-file",
            "b",
            "--password-file",
            "p",
            "--dom-domain",
            &domain,
            "--privacy-policy-hash",
            &policy,
        ]))
        .is_err());
        assert!(parse_arguments(args(&[
            "verify",
            "--backup-file",
            "a",
            "--password-file",
            "p",
            "--dom-domain",
            &"ab".repeat(32).to_uppercase(),
        ]))
        .is_err());
    }

    #[test]
    fn privacy_policy_mismatch_fails_before_reading_the_password_file() {
        let action = parse_arguments(args(&[
            "create",
            "--backup-file",
            "/missing/backup",
            "--password-file",
            "/missing/password",
            "--dom-domain",
            &"11".repeat(32),
            "--privacy-policy-hash",
            &"00".repeat(32),
        ]))
        .unwrap();
        let Action::Run(arguments) = action else {
            panic!("expected run action")
        };
        let error = execute(*arguments).err().unwrap();
        assert!(error
            .to_string()
            .contains("compiled privacy policy does not match"));
    }

    #[cfg(unix)]
    #[test]
    fn ceremony_creates_once_and_restores_the_same_public_address() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let password_file = directory.path().join("password");
        std::fs::write(&password_file, b"test-only recovery password").unwrap();
        std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_passphrase_file(&password_file).is_ok());
        let backup_file = directory.path().join("recovery.backup");
        let policy = hex::encode(privacy_policy_hash().as_bytes());
        let create = parse_arguments(args(&[
            "create",
            "--backup-file",
            backup_file.to_str().unwrap(),
            "--password-file",
            password_file.to_str().unwrap(),
            "--dom-domain",
            &"11".repeat(32),
            "--privacy-policy-hash",
            &policy,
        ]))
        .unwrap();
        let Action::Run(create) = create else {
            panic!("expected create action")
        };
        let created = execute((*create).clone()).unwrap();
        let expected_address = hex::encode(&created.recipient_address);
        let verify = parse_arguments(args(&[
            "verify",
            "--backup-file",
            backup_file.to_str().unwrap(),
            "--password-file",
            password_file.to_str().unwrap(),
            "--dom-domain",
            &"11".repeat(32),
            "--privacy-policy-hash",
            &policy,
            "--expected-address",
            &expected_address,
        ]))
        .unwrap();
        let Action::Run(verify) = verify else {
            panic!("expected verify action")
        };
        assert_eq!(execute(*verify).unwrap(), created);
        let mut wrong_address = created.recipient_address.clone();
        *wrong_address.last_mut().unwrap() ^= 1;
        let wrong_address = hex::encode(wrong_address);
        let wrong = parse_arguments(args(&[
            "verify",
            "--backup-file",
            backup_file.to_str().unwrap(),
            "--password-file",
            password_file.to_str().unwrap(),
            "--dom-domain",
            &"11".repeat(32),
            "--privacy-policy-hash",
            &policy,
            "--expected-address",
            &wrong_address,
        ]))
        .unwrap();
        let Action::Run(wrong) = wrong else {
            panic!("expected verify action")
        };
        assert!(execute(*wrong).is_err());
        assert!(execute(*create).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn password_loader_rejects_insecure_permissions_and_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let password = directory.path().join("password");
        std::fs::write(&password, b"test-only recovery password").unwrap();
        std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_passphrase_file(&password).is_err());
        std::fs::set_permissions(&password, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("password-link");
        symlink(&password, &link).unwrap();
        assert!(load_passphrase_file(&link).is_err());
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(load_passphrase_file(&password).is_err());
    }

    #[test]
    fn help_is_the_only_valueless_action() {
        assert!(matches!(
            parse_arguments(args(&["--help"])).unwrap(),
            Action::Help
        ));
        assert!(parse_arguments(args(&["--help", "extra"])).is_err());
    }
}
