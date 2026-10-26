//! Descriptor-anchored, owner-only directory staging and no-replace publish.

use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

use rand::RngCore;
use rustix::fs::{
    fchmod, fsync, mkdirat, openat, renameat, renameat_with, unlinkat, AtFlags, Mode, OFlags,
    RenameFlags,
};

/// Retained authority over one existing owner-only output directory.
pub struct PrivateDirectoryAuthority {
    directory: File,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl PrivateDirectoryAuthority {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let named = std::fs::symlink_metadata(path)?;
        if !named.file_type().is_dir()
            || named.file_type().is_symlink()
            || named.uid() != rustix::process::geteuid().as_raw()
            || named.permissions().mode() & 0o077 != 0
        {
            anyhow::bail!("private output must be a direct current-user owner-only directory");
        }
        let directory = File::open(path)?;
        let opened = directory.metadata()?;
        if opened.dev() != named.dev()
            || opened.ino() != named.ino()
            || opened.uid() != named.uid()
            || opened.permissions().mode() & 0o077 != 0
        {
            anyhow::bail!("private output directory changed during open");
        }
        Ok(Self {
            directory,
            path: path.to_path_buf(),
            device: opened.dev(),
            inode: opened.ino(),
        })
    }

    pub fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    pub fn invalidate_where(&self, predicate: impl Fn(&str) -> bool) -> anyhow::Result<()> {
        self.audit_path()?;
        for entry in std::fs::read_dir(self.path())? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(text) = name.to_str() else { continue };
            if predicate(text) {
                match unlinkat(self.directory.as_fd(), &name, AtFlags::empty()) {
                    Ok(()) | Err(rustix::io::Errno::NOENT) => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        fsync(self.directory.as_fd())?;
        self.audit_path()
    }

    /// Stage every file privately, then replace the named generation. Any
    /// publication failure removes every target name so consumers never see a
    /// falsely complete mixed generation.
    pub fn replace_files(
        &self,
        files: &[(String, Vec<u8>)],
        commit_names: &[&str],
    ) -> anyhow::Result<()> {
        self.audit_path()?;
        if files.is_empty() || commit_names.is_empty() {
            anyhow::bail!("private output generation or commit set is empty");
        }
        let mut names = BTreeSet::new();
        for (name, _) in files {
            validate_child_name(name)?;
            if !names.insert(name.as_str()) {
                anyhow::bail!("private output generation contains duplicate names");
            }
        }
        let mut commits = BTreeSet::new();
        for commit_name in commit_names {
            validate_child_name(commit_name)?;
            if !commits.insert(*commit_name) {
                anyhow::bail!("private output generation contains duplicate commit names");
            }
            if !names.contains(commit_name) {
                anyhow::bail!("private output generation omits a declared commit file");
            }
        }

        let mut staged: Vec<(OsString, &str, &[u8])> = Vec::with_capacity(files.len());
        let result = (|| -> anyhow::Result<()> {
            for (name, bytes) in files {
                let (temporary, mut file) = self.create_temporary()?;
                staged.push((temporary, name, bytes));
                fchmod(file.as_fd(), Mode::from_raw_mode(0o600))?;
                file.write_all(bytes)?;
                file.sync_all()?;
                let metadata = file.metadata()?;
                if !metadata.file_type().is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.nlink() != 1
                    || metadata.uid() != rustix::process::geteuid().as_raw()
                    || metadata.permissions().mode() & 0o777 != 0o600
                    || metadata.len() != bytes.len() as u64
                {
                    anyhow::bail!("staged private output identity is invalid");
                }
            }
            self.audit_path()?;
            for (temporary, name, _) in &staged {
                if commits.contains(name) {
                    continue;
                }
                renameat(
                    self.directory.as_fd(),
                    temporary,
                    self.directory.as_fd(),
                    *name,
                )?;
            }
            for commit_name in commit_names {
                let (temporary, name, _) =
                    staged
                        .iter()
                        .find(|(_, name, _)| name == commit_name)
                        .ok_or_else(|| anyhow::anyhow!("declared commit file was not staged"))?;
                renameat(
                    self.directory.as_fd(),
                    temporary,
                    self.directory.as_fd(),
                    *name,
                )?;
            }
            fsync(self.directory.as_fd())?;
            self.audit_path()?;
            for (_, name, expected) in &staged {
                let mut file = openat(
                    self.directory.as_fd(),
                    *name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map(File::from)?;
                let metadata = file.metadata()?;
                if !metadata.file_type().is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.nlink() != 1
                    || metadata.uid() != rustix::process::geteuid().as_raw()
                    || metadata.permissions().mode() & 0o777 != 0o600
                    || metadata.len() != expected.len() as u64
                {
                    anyhow::bail!("published private output identity is invalid");
                }
                let mut actual = Vec::with_capacity(expected.len());
                (&mut file)
                    .take(expected.len() as u64 + 1)
                    .read_to_end(&mut actual)?;
                if actual.as_slice() != *expected {
                    anyhow::bail!("published private output bytes differ from staged generation");
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            for (temporary, name, _) in &staged {
                let _ = unlinkat(self.directory.as_fd(), temporary, AtFlags::empty());
                let _ = unlinkat(self.directory.as_fd(), *name, AtFlags::empty());
            }
            let _ = fsync(self.directory.as_fd());
            return Err(error);
        }
        Ok(())
    }

    fn create_temporary(&self) -> anyhow::Result<(OsString, File)> {
        for _ in 0..32 {
            let mut random = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut random);
            let name = OsString::from(format!(".usdom-private-output-{}.tmp", hex::encode(random)));
            match openat(
                self.directory.as_fd(),
                &name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(descriptor) => return Ok((name, File::from(descriptor))),
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("could not allocate a private output temporary name")
    }

    fn audit_path(&self) -> anyhow::Result<()> {
        let named = std::fs::symlink_metadata(&self.path)?;
        let opened = self.directory.metadata()?;
        if !named.file_type().is_dir()
            || named.file_type().is_symlink()
            || named.dev() != self.device
            || named.ino() != self.inode
            || opened.dev() != self.device
            || opened.ino() != self.inode
            || named.uid() != rustix::process::geteuid().as_raw()
            || named.permissions().mode() & 0o077 != 0
        {
            anyhow::bail!("private output directory path changed");
        }
        Ok(())
    }
}

fn validate_child_name(name: &str) -> anyhow::Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
        || name.starts_with('.')
    {
        anyhow::bail!("private output name is not one canonical child component");
    }
    Ok(())
}

/// An unpublished directory whose namespace remains anchored to one retained
/// private parent descriptor for its entire lifetime.
pub struct PrivateStagingDirectory {
    parent: File,
    parent_path: PathBuf,
    parent_device: u64,
    parent_inode: u64,
    temporary_name: OsString,
    destination_name: OsString,
    directory: File,
    published: bool,
}

impl PrivateStagingDirectory {
    /// Create a fresh 0700 staging directory beside `destination`.
    pub fn create(destination: &Path) -> anyhow::Result<Self> {
        let parent_path = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| anyhow::anyhow!("private destination must have an explicit parent"))?;
        let destination_name = destination
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("private destination has no file name"))?
            .to_os_string();
        let named = std::fs::symlink_metadata(parent_path)?;
        if !named.file_type().is_dir()
            || named.file_type().is_symlink()
            || named.uid() != rustix::process::geteuid().as_raw()
            || named.permissions().mode() & 0o777 != 0o700
        {
            anyhow::bail!(
                "private staging parent must be a direct current-user mode-0700 directory"
            );
        }
        let parent = File::open(parent_path)?;
        let opened = parent.metadata()?;
        if opened.dev() != named.dev()
            || opened.ino() != named.ino()
            || opened.uid() != named.uid()
            || opened.permissions().mode() & 0o777 != 0o700
        {
            anyhow::bail!("private staging parent changed during open");
        }

        for _ in 0..32 {
            let mut random = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut random);
            let temporary_name =
                OsString::from(format!(".usdom-private-stage-{}.tmp", hex::encode(random)));
            match mkdirat(parent.as_fd(), &temporary_name, Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    let opened_directory = (|| -> anyhow::Result<File> {
                        let directory = openat(
                            parent.as_fd(),
                            &temporary_name,
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                        .map(File::from)?;
                        fchmod(directory.as_fd(), Mode::from_raw_mode(0o700))?;
                        let metadata = directory.metadata()?;
                        if !metadata.is_dir()
                            || metadata.uid() != rustix::process::geteuid().as_raw()
                            || metadata.permissions().mode() & 0o777 != 0o700
                        {
                            anyhow::bail!("private staging directory identity is invalid");
                        }
                        fsync(directory.as_fd())?;
                        fsync(parent.as_fd())?;
                        Ok(directory)
                    })();
                    let directory = match opened_directory {
                        Ok(directory) => directory,
                        Err(error) => {
                            let _ = unlinkat(parent.as_fd(), &temporary_name, AtFlags::REMOVEDIR);
                            let _ = fsync(parent.as_fd());
                            return Err(error);
                        }
                    };
                    return Ok(Self {
                        parent,
                        parent_path: parent_path.to_path_buf(),
                        parent_device: opened.dev(),
                        parent_inode: opened.ino(),
                        temporary_name,
                        destination_name,
                        directory,
                        published: false,
                    });
                }
                Err(rustix::io::Errno::EXIST) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("could not allocate a private staging directory")
    }

    /// A path rooted at the retained directory descriptor, suitable for child
    /// creation by APIs that accept paths only.
    pub fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
    }

    /// Durably create one exact owner-only child without following or
    /// replacing any existing directory entry.
    pub fn write_child_noclobber(&self, name: &str, bytes: &[u8]) -> anyhow::Result<()> {
        validate_child_name(name)?;
        let mut created = false;
        let result = (|| -> anyhow::Result<()> {
            let mut file = openat(
                self.directory.as_fd(),
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map(File::from)?;
            created = true;
            fchmod(file.as_fd(), Mode::from_raw_mode(0o600))?;
            file.write_all(bytes)?;
            file.sync_all()?;
            let metadata = file.metadata()?;
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.nlink() != 1
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.permissions().mode() & 0o777 != 0o600
                || metadata.len() != bytes.len() as u64
            {
                anyhow::bail!("private staging child identity is invalid");
            }
            fsync(self.directory.as_fd())?;
            Ok(())
        })();
        if result.is_err() && created {
            let _ = unlinkat(self.directory.as_fd(), name, AtFlags::empty());
            let _ = fsync(self.directory.as_fd());
        }
        result
    }

    /// Publish the complete staged directory without replacing any existing
    /// destination entry.
    pub fn publish(mut self) -> anyhow::Result<()> {
        self.audit_parent_path()?;
        self.audit_private_children()?;
        fsync(self.directory.as_fd())?;
        renameat_with(
            self.parent.as_fd(),
            &self.temporary_name,
            self.parent.as_fd(),
            &self.destination_name,
            RenameFlags::NOREPLACE,
        )?;
        self.published = true;
        fsync(self.parent.as_fd())?;
        self.audit_parent_path()?;
        let published = openat(
            self.parent.as_fd(),
            &self.destination_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map(File::from)?;
        let expected = self.directory.metadata()?;
        let actual = published.metadata()?;
        if expected.dev() != actual.dev()
            || expected.ino() != actual.ino()
            || actual.uid() != rustix::process::geteuid().as_raw()
            || actual.permissions().mode() & 0o777 != 0o700
        {
            anyhow::bail!("published private directory differs from staged authority");
        }
        Ok(())
    }

    /// Reject any child created through a path-only API unless it is the same
    /// direct, owner-only regular inode observed through the retained staging
    /// descriptor. This covers wallet snapshot writers that cannot use openat.
    fn audit_private_children(&self) -> anyhow::Result<()> {
        const MAX_STAGED_CHILDREN: usize = 64;
        let mut count = 0usize;
        for entry in std::fs::read_dir(self.path())? {
            let entry = entry?;
            count = count
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("private staging child count overflow"))?;
            if count > MAX_STAGED_CHILDREN {
                anyhow::bail!("private staging directory contains too many children");
            }
            let name = entry.file_name();
            let name_text = name
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("private staging child name is not UTF-8"))?;
            validate_child_name(name_text)?;
            let named = entry.metadata()?;
            let opened = openat(
                self.directory.as_fd(),
                &name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)?;
            let actual = opened.metadata()?;
            if !named.file_type().is_file()
                || named.file_type().is_symlink()
                || named.dev() != actual.dev()
                || named.ino() != actual.ino()
                || actual.nlink() != 1
                || actual.uid() != rustix::process::geteuid().as_raw()
                || actual.permissions().mode() & 0o777 != 0o600
            {
                anyhow::bail!("private staging child identity is invalid before publish");
            }
        }
        Ok(())
    }

    fn audit_parent_path(&self) -> anyhow::Result<()> {
        let named = std::fs::symlink_metadata(&self.parent_path)?;
        let opened = self.parent.metadata()?;
        if !named.file_type().is_dir()
            || named.file_type().is_symlink()
            || named.dev() != self.parent_device
            || named.ino() != self.parent_inode
            || opened.dev() != self.parent_device
            || opened.ino() != self.parent_inode
            || named.uid() != rustix::process::geteuid().as_raw()
            || named.permissions().mode() & 0o777 != 0o700
        {
            anyhow::bail!("private staging parent path changed")
        }
        Ok(())
    }
}

impl Drop for PrivateStagingDirectory {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        let path = PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            self.parent.as_raw_fd(),
            self.temporary_name.to_string_lossy()
        ));
        let _ = std::fs::remove_dir_all(path);
        let _ = fsync(self.parent.as_fd());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn private_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[test]
    fn stages_privately_and_publishes_without_replacement() {
        let root = private_root();
        let destination = root.path().join("wallet-state");
        let staging = PrivateStagingDirectory::create(&destination).unwrap();
        staging.write_child_noclobber("state", b"exact").unwrap();
        assert!(staging
            .write_child_noclobber("state", b"replacement")
            .is_err());
        assert_eq!(
            std::fs::read(staging.path().join("state")).unwrap(),
            b"exact"
        );
        staging.publish().unwrap();
        assert_eq!(std::fs::read(destination.join("state")).unwrap(), b"exact");

        let second = PrivateStagingDirectory::create(&destination).unwrap();
        std::fs::write(second.path().join("state"), b"replacement").unwrap();
        assert!(second.publish().is_err());
        assert_eq!(std::fs::read(destination.join("state")).unwrap(), b"exact");
    }

    #[test]
    fn rejects_indirect_or_nonprivate_parent() {
        let root = private_root();
        let real = root.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let linked = root.path().join("linked");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        assert!(PrivateStagingDirectory::create(&linked.join("state")).is_err());

        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(PrivateStagingDirectory::create(&real.join("state")).is_err());
    }

    #[test]
    fn retained_output_authority_replaces_exact_generation_and_invalidates_by_name() {
        let root = private_root();
        let authority = PrivateDirectoryAuthority::open(root.path()).unwrap();
        authority
            .replace_files(
                &[
                    ("a.bin".into(), b"first-a".to_vec()),
                    ("b.json".into(), b"first-b".to_vec()),
                ],
                &["b.json"],
            )
            .unwrap();
        authority
            .replace_files(
                &[
                    ("a.bin".into(), b"second-a".to_vec()),
                    ("b.json".into(), b"second-b".to_vec()),
                ],
                &["b.json"],
            )
            .unwrap();
        assert_eq!(
            std::fs::read(root.path().join("a.bin")).unwrap(),
            b"second-a"
        );
        assert_eq!(
            std::fs::read(root.path().join("b.json")).unwrap(),
            b"second-b"
        );
        assert!(authority
            .replace_files(&[("../escape".into(), b"bad".to_vec())], &["../escape"])
            .is_err());
        assert!(authority
            .replace_files(&[("a.bin".into(), b"bad".to_vec())], &["missing.json"])
            .is_err());
        let blocked_commit = root.path().join("blocked.json");
        std::fs::create_dir(&blocked_commit).unwrap();
        assert!(authority
            .replace_files(
                &[
                    (
                        "published-before-commit.bin".into(),
                        b"must disappear".to_vec(),
                    ),
                    ("blocked.json".into(), b"commit".to_vec()),
                ],
                &["blocked.json"],
            )
            .is_err());
        assert!(!root.path().join("published-before-commit.bin").exists());
        assert!(blocked_commit.is_dir());
        authority
            .invalidate_where(|name| name.ends_with(".bin"))
            .unwrap();
        assert!(!root.path().join("a.bin").exists());
        assert!(root.path().join("b.json").exists());
    }
}
