use cap_std::ambient_authority;
use cap_std::fs::Dir;
use std::io;
use std::path::{Path, PathBuf};

/// Capability-based Project Jail to prevent path traversal and arbitrary system file access
#[allow(dead_code)]
pub struct ProjectJail {
    root_dir: Dir,
    canonical_root: PathBuf,
}

#[allow(dead_code)]
impl ProjectJail {
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let canonical_root = std::fs::canonicalize(path.as_ref())?;
        let root_dir = Dir::open_ambient_dir(&canonical_root, ambient_authority())?;
        Ok(Self {
            root_dir,
            canonical_root,
        })
    }

    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    /// Read file scoped strictly within the project boundary
    pub fn read_file<P: AsRef<Path>>(&self, relative_path: P) -> io::Result<String> {
        let clean_path = self.sanitize_path(relative_path.as_ref())?;
        self.root_dir.read_to_string(clean_path)
    }

    /// Read binary bytes scoped strictly within the project boundary
    pub fn read_bytes<P: AsRef<Path>>(&self, relative_path: P) -> io::Result<Vec<u8>> {
        let clean_path = self.sanitize_path(relative_path.as_ref())?;
        self.root_dir.read(clean_path)
    }

    /// Write file scoped strictly within the project boundary
    pub fn write_file<P: AsRef<Path>, C: AsRef<[u8]>>(&self, relative_path: P, content: C) -> io::Result<()> {
        let clean_path = self.sanitize_path(relative_path.as_ref())?;
        if let Some(parent) = clean_path.parent() {
            if !parent.as_os_str().is_empty() {
                self.root_dir.create_dir_all(parent)?;
            }
        }
        self.root_dir.write(clean_path, content.as_ref())
    }

    /// Check if path exists inside jail
    pub fn exists<P: AsRef<Path>>(&self, relative_path: P) -> bool {
        if let Ok(clean_path) = self.sanitize_path(relative_path.as_ref()) {
            self.root_dir.exists(clean_path)
        } else {
            false
        }
    }

    fn sanitize_path<'a>(&self, path: &'a Path) -> io::Result<&'a Path> {
        if path.is_absolute() {
            if let Ok(stripped) = path.strip_prefix(&self.canonical_root) {
                return Ok(stripped);
            }
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Access denied: Path {} is outside project jail", path.display()),
            ));
        }

        // Detect path traversal attempts
        for component in path.components() {
            if let std::path::Component::ParentDir = component {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Access denied: Directory traversal ('..') is strictly prohibited",
                ));
            }
        }

        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jail_confinement() {
        let jail = ProjectJail::open(".").expect("Must open current dir as jail");
        assert!(jail.read_file("Cargo.toml").is_ok());
        assert!(jail.read_file("../../etc/passwd").is_err());
    }
}
