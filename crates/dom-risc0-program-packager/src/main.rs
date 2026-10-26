//! Package one user ELF with the pinned RISC Zero v1 compatibility kernel.
#![deny(unsafe_code)]

use risc0_binfmt::{compute_image_id, ProgramBinary};
use risc0_zkos_v1compat::V1COMPAT_ELF;
use std::{
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_USER_ELF_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROGRAM_BYTES: usize = 128 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn anchored_child(parent: &File, child: &Path) -> io::Result<PathBuf> {
    let name = child.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no final component")
    })?;
    if name == "." || name == ".." {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid final component",
        ));
    }
    Ok(PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(name))
}

fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn open_parent(path: &Path) -> io::Result<(File, fs::Metadata)> {
    let parent_path = path.parent().unwrap_or_else(|| Path::new("."));
    let named = fs::symlink_metadata(parent_path)?;
    if !named.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "parent is not a direct directory",
        ));
    }
    let parent = File::open(parent_path)?;
    if !same_file(&named, &parent.metadata()?) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "parent changed while opening",
        ));
    }
    Ok((parent, named))
}

fn verify_parent(path: &Path, parent: &File, expected: &fs::Metadata) -> io::Result<()> {
    let named = fs::symlink_metadata(path.parent().unwrap_or_else(|| Path::new(".")))?;
    if !same_file(expected, &parent.metadata()?) || !same_file(expected, &named) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "parent directory changed",
        ));
    }
    Ok(())
}

fn read_captured(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let (parent, parent_identity) = open_parent(path)?;
    let anchored = anchored_child(&parent, path)?;
    let named = fs::symlink_metadata(&anchored)?;
    if !named.file_type().is_file() || named.nlink() != 1 || named.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input is not an eligible regular file",
        ));
    }
    let mut input = File::open(&anchored)?;
    let opened = input.metadata()?;
    if !same_file(&named, &opened) || opened.nlink() != 1 || opened.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input changed while opening",
        ));
    }
    let capacity = usize::try_from(opened.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "input length is not representable",
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut input)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    let after = input.metadata()?;
    verify_parent(path, &parent, &parent_identity)?;
    if bytes.len() as u64 != opened.len()
        || bytes.len() as u64 > maximum
        || !same_file(&opened, &after)
        || after.len() != opened.len()
        || after.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input changed while reading",
        ));
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_PROGRAM_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ProgramBinary exceeds size limit",
        ));
    }
    let (parent, parent_identity) = open_parent(path)?;
    let target = anchored_child(&parent, path)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_name = format!(
        ".dom-risc0-package.{}.{}.{}.tmp",
        std::process::id(),
        nonce,
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    );
    let temp = anchored_child(&parent, Path::new(&temp_name))?;
    let mut published_identity = None;
    let result = (|| {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        let created = output.metadata()?;
        if !created.file_type().is_file() || created.nlink() != 1 || created.mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "temporary output is not a private singly-linked regular file",
            ));
        }
        output.write_all(bytes)?;
        output.sync_all()?;
        published_identity = Some(output.metadata()?);
        drop(output);
        verify_parent(path, &parent, &parent_identity)?;
        fs::rename(&temp, &target)?;
        parent.sync_all()?;
        if read_captured(path, MAX_PROGRAM_BYTES as u64)? != bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "published ProgramBinary did not verify",
            ));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
        if let (Some(expected), Ok(current)) = (published_identity, fs::symlink_metadata(&target)) {
            if current.file_type().is_file() && same_file(&expected, &current) {
                let _ = fs::remove_file(&target);
                let _ = parent.sync_all();
            }
        }
    }
    result
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let first = args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing user ELF path or --verify",
        )
    })?;
    if first == "--verify" {
        let input = PathBuf::from(args.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing ProgramBinary path")
        })?);
        let expected = args
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing expected ImageID"))?
            .into_string()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ImageID is not UTF-8"))?;
        if args.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unexpected trailing argument",
            )
            .into());
        }
        if expected.len() != 64
            || !expected
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected ImageID must be 64 lowercase hexadecimal characters",
            )
            .into());
        }
        let bytes = read_captured(&input, MAX_PROGRAM_BYTES as u64)?;
        let program = ProgramBinary::decode(&bytes)?;
        if program.encode() != bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "noncanonical ProgramBinary encoding",
            )
            .into());
        }
        let actual = program.compute_image_id()?.to_string();
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ProgramBinary ImageID mismatch: expected {expected}, got {actual}"),
            )
            .into());
        }
        println!("{actual}");
        return Ok(());
    }
    let input = PathBuf::from(first);
    let output = PathBuf::from(args.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "missing ProgramBinary output path",
        )
    })?);
    if args.next().is_some() {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "unexpected trailing argument").into(),
        );
    }
    let binary =
        ProgramBinary::new(&read_captured(&input, MAX_USER_ELF_BYTES)?, V1COMPAT_ELF).encode();
    atomic_write(&output, &binary)?;
    println!("{}", compute_image_id(&binary)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    fn root(label: &str) -> PathBuf {
        let path = env::temp_dir().join(format!(
            "dom-packager-{label}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }
    #[test]
    fn captured_read_rejects_links_and_oversize() {
        let dir = root("read");
        let direct = dir.join("direct");
        fs::write(&direct, b"abc").unwrap();
        assert_eq!(read_captured(&direct, 3).unwrap(), b"abc");
        assert!(read_captured(&direct, 2).is_err());
        let symbolic = dir.join("symbolic");
        symlink(&direct, &symbolic).unwrap();
        assert!(read_captured(&symbolic, 3).is_err());
        let hard = dir.join("hard");
        fs::hard_link(&direct, &hard).unwrap();
        assert!(read_captured(&direct, 3).is_err());
        let linked_parent = dir.with_extension("link");
        symlink(&dir, &linked_parent).unwrap();
        assert!(read_captured(&linked_parent.join("direct"), 3).is_err());
        fs::remove_file(linked_parent).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn atomic_write_is_exact_and_private() {
        let dir = root("write");
        let target = dir.join("program.bin");
        atomic_write(&target, b"first").unwrap();
        atomic_write(&target, b"replacement").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"replacement");
        assert_eq!(fs::metadata(&target).unwrap().mode() & 0o777, 0o600);
        fs::remove_dir_all(dir).unwrap();
    }
}
