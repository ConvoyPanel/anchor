//! Provisioner snippets: the cloud-init files that carry a server's provisioner
//! scripts onto its first boot.
//!
//! Proxmox reads custom cloud-init (`cicustom`) only from a file on a storage
//! with the `snippets` content type, and its API has no way to upload one. The
//! panel decides what goes in the file, which storage it lands on and when it
//! goes away; all this module does is put the exact bytes it was handed into
//! the one file the token names, and take that file away again.
//!
//! Two rules hold everywhere in here. Anchor only ever touches files named
//! `convoy-*.yaml`, so an admin's own snippets on the same storage are out of
//! reach whatever a token says. And a snippet's contents are never logged: the
//! panel encodes a customer's field values into them, so as far as Anchor is
//! concerned they are secrets.

use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::{process::Command, sync::Notify};

use crate::{
    config::AgentConfig,
    error::{Error, Result},
    templates::command,
};

/// The largest body a write accepts. Vendor data is a handful of base64
/// encoded scripts; anything near this is a mistake, not a provisioner.
pub const MAX_SNIPPET_BYTES: usize = 1024 * 1024;

const NAME_PREFIX: &str = "convoy-";
const NAME_SUFFIX: &str = ".yaml";
/// `[a-z0-9][a-z0-9-]{0,95}`: the part of the name between the two fixed ends.
const NAME_STEM_MAX: usize = 96;

/// The directory name Proxmox keeps a storage's snippets in.
const SNIPPETS_DIR: &str = "snippets";

/// Long enough for `pvesm status` to activate a slow network storage, short
/// enough that a hung NFS mount fails the request rather than the panel's
/// patience. The runner kills `pvesm` when this elapses.
const PVESM_TIMEOUT: Duration = Duration::from_secs(30);

/// One snippet a token named, once its name and storage have passed the
/// checks. The only way to reach the filesystem, so nothing can write or delete
/// a snippet that has not been validated first.
#[derive(Clone, Debug)]
pub struct Snippet {
    storage: String,
    name: String,
}

/// What a write reports back: the volume id the panel hands to
/// `qm set --cicustom`, and the digest and size of what actually landed.
#[derive(Debug, Serialize)]
pub struct Written {
    pub volume: String,
    pub sha256: String,
    pub size: u64,
}

impl Snippet {
    /// Name first, then storage: a name outside Anchor's namespace is refused
    /// whatever storage it was aimed at.
    pub fn new(storage: &str, name: &str) -> Result<Self> {
        validate_name(name)?;
        validate_storage(storage)?;

        Ok(Self {
            storage: storage.to_owned(),
            name: name.to_owned(),
        })
    }

    /// The Proxmox volume id, `<storage>:snippets/<name>`.
    pub fn volume(&self) -> String {
        format!("{}:{SNIPPETS_DIR}/{}", self.storage, self.name)
    }

    /// Write `contents` over this snippet, provided they are the bytes the
    /// token was minted for.
    ///
    /// The digest is checked before anything touches the node, so a body the
    /// panel did not send never costs a `pvesm` call, let alone a file.
    pub async fn write(
        &self,
        agent: &AgentConfig,
        sha256: &str,
        contents: Vec<u8>,
    ) -> Result<Written> {
        let digest = hex::encode(Sha256::digest(&contents));
        if !digest.eq_ignore_ascii_case(sha256) {
            return Err(Error::InvalidSnippet(format!(
                "the body of {} does not match the sha256 its token was minted for",
                self.name
            )));
        }

        let path = self.locate(agent).await?;
        let size = contents.len() as u64;

        let target = path.clone();
        tokio::task::spawn_blocking(move || write_atomically(&target, &contents))
            .await
            .map_err(|error| io::Error::other(error.to_string()))?
            .inspect_err(|error| {
                tracing::warn!(path = %path.display(), %error, "could not write a snippet");
            })?;

        Ok(Written {
            volume: self.volume(),
            sha256: digest,
            size,
        })
    }

    /// Remove this snippet. `false` when there was nothing to remove, which is
    /// a success: the panel retries a cleanup without having to special-case
    /// one that already happened.
    ///
    /// Except when the storage itself is not there. A file missing from a
    /// storage whose root has gone is not known to be gone, and saying it was
    /// would end a cleanup that may still have something to clean.
    pub async fn delete(&self, agent: &AgentConfig) -> Result<bool> {
        let path = self.locate(agent).await?;

        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let root = path.parent().and_then(Path::parent);
                if let Some(root) = root
                    && tokio::fs::metadata(root).await.is_err()
                {
                    return Err(missing_root(root));
                }
                Ok(false)
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "could not delete a snippet");
                Err(error.into())
            }
        }
    }

    /// Where this snippet lives on this node, as Proxmox itself resolves it.
    ///
    /// `pvesm` rather than a path built here, because a storage's mount point
    /// is its configuration -- an NFS share under `/mnt/pve`, a directory
    /// storage anywhere an admin likes -- and guessing it would one day write a
    /// customer's secrets somewhere Proxmox will never read them.
    async fn locate(&self, agent: &AgentConfig) -> Result<PathBuf> {
        let status = pvesm(agent, &["status", "--content", SNIPPETS_DIR]).await?;
        check_status(&status, &self.storage)?;

        let volume = self.volume();
        let printed = pvesm(agent, &["path", &volume]).await?;
        let Some(resolved) = printed
            .iter()
            .map(|line| line.trim())
            .rfind(|line| !line.is_empty())
        else {
            tracing::warn!(volume, "pvesm path printed nothing");
            return Err(Error::Pvesm(format!("pvesm path {volume} printed nothing")));
        };

        check_resolved(&volume, resolved, &self.name)
    }
}

/// `^convoy-[a-z0-9][a-z0-9-]{0,95}\.yaml$`, spelled out rather than pulled in
/// as a regex engine for one pattern.
fn validate_name(name: &str) -> Result<()> {
    let stem = name
        .strip_prefix(NAME_PREFIX)
        .and_then(|rest| rest.strip_suffix(NAME_SUFFIX));

    let valid = stem.is_some_and(|stem| {
        let mut chars = stem.chars();
        stem.len() <= NAME_STEM_MAX
            && chars
                .next()
                .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    });

    if !valid {
        return Err(Error::InvalidSnippet(format!(
            "{name:?} is not a snippet name Anchor manages; it must look like convoy-<id>.yaml"
        )));
    }

    Ok(())
}

/// Proxmox's own rule for a storage id (`PVE::JSONSchema::parse_id`): a letter,
/// then letters, digits, `-`, `_` or `.`, ending in a letter or digit.
///
/// It matters beyond tidiness. The id is spliced into a volume id and handed
/// to `pvesm` as an argument, so one containing `:` or `/` would name some
/// other volume, and one starting with `-` would be read as a flag.
fn validate_storage(storage: &str) -> Result<()> {
    let bytes = storage.as_bytes();
    let valid = bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));

    if !valid {
        return Err(Error::SnippetStorage(format!(
            "{storage:?} is not a valid Proxmox storage id"
        )));
    }

    Ok(())
}

/// Read `pvesm status --content snippets` for one storage.
///
/// The filter does half the work: a storage without the `snippets` content
/// type is not listed at all. Of those that are, only `active` will do --
/// `inactive` is a network storage that is not mounted, and `disabled` is one
/// switched off or restricted to other nodes, and writing into either would put
/// the file somewhere Proxmox is not going to look.
fn check_status(lines: &[String], storage: &str) -> Result<()> {
    // Columns are Name, Type, Status, then sizes. The header is skipped by its
    // second column rather than its first, because `Name` is a valid storage
    // id and `Type` is not a storage type.
    let state = lines.iter().find_map(|line| {
        let mut columns = line.split_whitespace();
        let (name, kind, state) = (columns.next()?, columns.next()?, columns.next()?);
        (name == storage && kind != "Type").then_some(state)
    });

    match state {
        Some("active") => Ok(()),
        Some(state) => Err(Error::SnippetStorage(format!(
            "storage {storage} cannot hold snippets: it is {state} on this node"
        ))),
        None => Err(Error::SnippetStorage(format!(
            "storage {storage} cannot hold snippets: it does not exist on this node or does not \
             have the snippets content type enabled"
        ))),
    }
}

/// Refuse a resolved path Anchor has no business writing to.
///
/// `pvesm` is trusted to know where a storage lives, not to be the last line of
/// defence for a file holding someone's secrets. The path has to be absolute
/// and free of `..`, end in exactly the name the token gave, and sit directly
/// in a directory called `snippets`.
fn check_resolved(volume: &str, resolved: &str, name: &str) -> Result<PathBuf> {
    let path = PathBuf::from(resolved);

    let plain = path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    let named = path.file_name() == Some(OsStr::new(name));
    let in_snippets = path.parent().and_then(Path::file_name) == Some(OsStr::new(SNIPPETS_DIR));

    if !(plain && named && in_snippets) {
        return Err(Error::SnippetStorage(format!(
            "pvesm resolved {volume} to {resolved}, which is not a file in a snippets directory"
        )));
    }

    Ok(path)
}

/// Write a snippet so that Proxmox only ever sees the old file or the new one.
///
/// A temporary file in the same directory (so the rename cannot cross a
/// filesystem), created exclusively with mode `0600`, fsynced, then renamed
/// over the target. A guest that starts while this runs reads a whole snippet
/// or none, never half of one.
fn write_atomically(target: &Path, contents: &[u8]) -> Result<()> {
    let dir = target
        .parent()
        .expect("a checked snippet path has a parent");
    ensure_snippets_dir(dir)?;

    let name = target
        .file_name()
        .and_then(OsStr::to_str)
        .expect("a checked snippet path ends in its name");
    let temporary = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));

    if let Err(error) = write_then_rename(&temporary, target, contents) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }

    // Make the rename itself durable. Best effort: some network filesystems
    // refuse to fsync a directory, and the file is already complete.
    if let Err(error) = File::open(dir).and_then(|dir| dir.sync_all()) {
        tracing::debug!(dir = %dir.display(), %error, "could not fsync the snippets directory");
    }

    Ok(())
}

fn write_then_rename(temporary: &Path, target: &Path, contents: &[u8]) -> io::Result<()> {
    // `create_new` so a file or symlink already at the temporary name is never
    // followed, and 0600 from the first byte rather than after it.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;

    std::fs::rename(temporary, target)
}

/// Create the `snippets` directory itself if it is missing, and nothing above
/// it.
///
/// What keeps a write off an unmounted share is the `active` check; this is
/// the backstop behind it. A storage whose root has gone altogether is not one
/// to write into, and creating the whole chain would leave a customer's
/// secrets on the node's own disk, somewhere no storage points.
fn ensure_snippets_dir(dir: &Path) -> Result<()> {
    match std::fs::create_dir(dir) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(missing_root(dir.parent().unwrap_or(dir)))
        }
        Err(error) => Err(error.into()),
    }
}

fn missing_root(root: &Path) -> Error {
    Error::SnippetStorage(format!(
        "the storage root {} does not exist on this node",
        root.display()
    ))
}

/// Run `pvesm` and hand back its stdout, line by line.
async fn pvesm(agent: &AgentConfig, args: &[&str]) -> Result<Vec<String>> {
    let program = agent.pvesm_path.as_str();
    let mut invocation = Command::new(program);
    invocation.args(args);

    // Nothing cancels a request-scoped call; the timeout does that job.
    let never = Notify::new();
    let mut lines = Vec::new();
    let outcome = tokio::time::timeout(
        PVESM_TIMEOUT,
        command::run(program, invocation, &never, |line| {
            lines.push(line.to_owned())
        }),
    )
    .await;

    let error = match outcome {
        Ok(Ok(())) => return Ok(lines),
        // The runner speaks in template errors, which are a caller's fault;
        // a failing `pvesm` is the node's.
        Ok(Err(Error::Template(detail))) => Error::Pvesm(detail),
        Ok(Err(other)) => other,
        Err(_) => Error::Pvesm(format!(
            "{program} {} did not finish within {} seconds",
            args.join(" "),
            PVESM_TIMEOUT.as_secs()
        )),
    };

    tracing::warn!(%error, "could not ask pvesm about snippet storage");
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(output: &str) -> Vec<String> {
        output.lines().map(str::to_owned).collect()
    }

    const STATUS: &str = "\
Name             Type     Status           Total            Used       Available        %
Name              dir     active        98497780        12345678        81234567   12.53%
local             dir     active        98497780        12345678        81234567   12.53%
nfs-share         nfs   inactive               0               0               0    0.00%
retired           dir   disabled               0               0               0      N/A
";

    #[test]
    fn accepts_the_names_the_panel_mints() {
        for name in [
            "convoy-provisioner-0b7e5b52-7f2c-4b8f-9b1e-3f6f0d6e2a11.yaml",
            "convoy-x.yaml",
            "convoy-0.yaml",
            &format!("convoy-{}.yaml", "a".repeat(NAME_STEM_MAX)),
        ] {
            assert!(validate_name(name).is_ok(), "{name} should be accepted");
        }
    }

    #[test]
    fn refuses_every_name_outside_anchors_namespace() {
        for name in [
            "foo.yaml",
            "convoy-x.yml",
            "convoy-.yaml",
            "convoy--x.yaml",
            "convoy-X.yaml",
            "convoy-x.yaml.tmp",
            ".convoy-x.yaml",
            "convoy-x",
            "convoy-.yaml.yaml",
            "../x.yaml",
            "convoy-../x.yaml",
            "convoy-a/b.yaml",
            "convoy-a b.yaml",
            "convoy-a\0.yaml",
            "convoy-é.yaml",
            "",
            &format!("convoy-{}.yaml", "a".repeat(NAME_STEM_MAX + 1)),
        ] {
            assert!(
                matches!(validate_name(name), Err(Error::InvalidSnippet(_))),
                "{name:?} should be refused"
            );
        }
    }

    #[test]
    fn accepts_the_storage_ids_proxmox_itself_uses() {
        for storage in [
            "local",
            "local-lvm",
            "nfs.backup",
            "ceph_pool1",
            "Snippets2",
        ] {
            assert!(validate_storage(storage).is_ok(), "{storage} should pass");
        }
    }

    #[test]
    fn refuses_a_storage_id_that_would_name_another_volume_or_a_flag() {
        for storage in [
            "", "a", "-rf", "1local", "local-", "local:x", "local/..", "..", "lo cal", "local\n",
        ] {
            assert!(
                matches!(validate_storage(storage), Err(Error::SnippetStorage(_))),
                "{storage:?} should be refused"
            );
        }
    }

    #[test]
    fn the_volume_id_is_proxmoxs_spelling() {
        let snippet = Snippet::new("local", "convoy-x.yaml").unwrap();

        assert_eq!(snippet.volume(), "local:snippets/convoy-x.yaml");
    }

    #[test]
    fn only_an_active_listed_storage_holds_snippets() {
        let status = lines(STATUS);

        assert!(check_status(&status, "local").is_ok());
        // A storage called `Name` is not mistaken for the header, nor the
        // header for it.
        assert!(check_status(&status, "Name").is_ok());

        for storage in ["nfs-share", "retired", "local-lvm"] {
            assert!(
                matches!(
                    check_status(&status, storage),
                    Err(Error::SnippetStorage(_))
                ),
                "{storage} should be refused"
            );
        }
    }

    #[test]
    fn says_why_a_storage_was_refused() {
        let status = lines(STATUS);

        let inactive = check_status(&status, "nfs-share").unwrap_err().to_string();
        assert!(inactive.contains("inactive"), "{inactive}");

        let missing = check_status(&status, "local-lvm").unwrap_err().to_string();
        assert!(missing.contains("snippets content type"), "{missing}");
    }

    #[test]
    fn accepts_a_path_in_a_snippets_directory() {
        for resolved in [
            "/var/lib/vz/snippets/convoy-x.yaml",
            "/mnt/pve/nfs-share/snippets/convoy-x.yaml",
        ] {
            let path = check_resolved("v", resolved, "convoy-x.yaml").unwrap();
            assert_eq!(path, PathBuf::from(resolved));
        }
    }

    #[test]
    fn refuses_a_path_anchor_has_no_business_writing_to() {
        for resolved in [
            "var/lib/vz/snippets/convoy-x.yaml",
            "/var/lib/vz/images/convoy-x.yaml",
            "/var/lib/vz/snippets/convoy-y.yaml",
            "/var/lib/vz/snippets/../../../etc/snippets/convoy-x.yaml",
            "/var/lib/vz/snippets/convoy-x.yaml/..",
            "/var/lib/vz/snippets/",
            "/etc/shadow",
            "",
        ] {
            assert!(
                matches!(
                    check_resolved("v", resolved, "convoy-x.yaml"),
                    Err(Error::SnippetStorage(_))
                ),
                "{resolved:?} should be refused"
            );
        }
    }

    #[test]
    fn writes_with_owner_only_permissions_and_leaves_no_temporary_behind() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("snippets").join("convoy-x.yaml");

        write_atomically(&target, b"#cloud-config\n").unwrap();
        write_atomically(&target, b"#cloud-config\nruncmd: []\n").unwrap();

        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"#cloud-config\nruncmd: []\n"
        );
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let entries: Vec<_> = std::fs::read_dir(target.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, [OsStr::new("convoy-x.yaml")]);
    }

    /// Writing through a storage whose root has gone would recreate it on the
    /// node's own disk.
    #[test]
    fn will_not_create_a_storage_root_that_is_not_there() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir
            .path()
            .join("unmounted")
            .join("snippets")
            .join("convoy-x.yaml");

        assert!(matches!(
            write_atomically(&target, b"#cloud-config\n"),
            Err(Error::SnippetStorage(_))
        ));
        assert!(!dir.path().join("unmounted").exists());
    }

    /// A symlink sitting at the target is replaced, never written through.
    #[test]
    fn replaces_a_symlink_at_the_target_rather_than_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let snippets = dir.path().join("snippets");
        std::fs::create_dir(&snippets).unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        let target = snippets.join("convoy-x.yaml");
        std::os::unix::fs::symlink(&victim, &target).unwrap();

        write_atomically(&target, b"#cloud-config\n").unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert!(!std::fs::symlink_metadata(&target).unwrap().is_symlink());
    }
}
