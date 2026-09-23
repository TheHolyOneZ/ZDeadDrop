use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};

use crate::error::{ImportError, Result};

pub const DEFAULT_IGNORES: &[&str] = &[
    "**/node_modules/**",
    "**/target/**",
    "**/.venv/**",
    "**/__pycache__/**",
    "**/dist/**",
    "**/build/**",
    "**/.DS_Store",
    "**/Thumbs.db",
    "**/*.swp",
    "**/.cache/**",
    "**/.git/**",
    "**/.svn/**",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub path: String,
    pub source: PathBuf,
    pub size: u64,
}

#[derive(Debug, Default)]
pub struct Walk {
    pub files: Vec<Found>,

    pub skipped: Vec<(String, String)>,
    pub total_bytes: u64,
}

impl Walk {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

pub fn walk(root: &Path, extra_ignores: &[String], use_defaults: bool) -> Result<Walk> {
    let mut builder = GlobSetBuilder::new();

    if use_defaults {
        for pattern in DEFAULT_IGNORES {
            builder.add(Glob::new(pattern).map_err(|e| ImportError::Parse(e.to_string()))?);
        }
    }
    for pattern in extra_ignores {
        builder.add(
            Glob::new(pattern)
                .map_err(|e| ImportError::Parse(format!("ignore pattern {pattern:?}: {e}")))?,
        );
    }
    let ignores: GlobSet = builder
        .build()
        .map_err(|e| ImportError::Parse(e.to_string()))?;

    let mut out = Walk::default();

    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                out.skipped.push((
                    e.path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                    "could not be read".to_string(),
                ));
                continue;
            }
        };

        if !entry.file_type().is_file() {
            if entry.file_type().is_symlink() {
                out.skipped.push((
                    entry.path().display().to_string(),
                    "symbolic link".to_string(),
                ));
            }
            continue;
        }

        let relative = entry.path().strip_prefix(root).unwrap_or(entry.path());
        let display = relative.to_string_lossy().replace('\\', "/");

        if ignores.is_match(relative) {
            out.skipped.push((display, "ignored".to_string()));
            continue;
        }

        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        out.total_bytes += size;
        out.files.push(Found {
            path: display,
            source: entry.path().to_path_buf(),
            size,
        });
    }

    out.files.sort_by(|a, b| a.path.cmp(&b.path));
    out.skipped.sort();

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignore_rules_do_not_look_above_the_chosen_folder() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir
            .path()
            .join("build")
            .join("target")
            .join("Family photos");
        std::fs::create_dir_all(root.join("2019")).unwrap();
        std::fs::write(root.join("2019/beach.jpg"), b"jpg").unwrap();
        std::fs::create_dir_all(root.join("node_modules")).unwrap();
        std::fs::write(root.join("node_modules/x.js"), b"junk").unwrap();

        let walk = walk(&root, &[], true).unwrap();
        let paths: Vec<_> = walk.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["2019/beach.jpg"]);
        assert_eq!(
            walk.skipped.len(),
            1,
            "node_modules inside is still skipped"
        );
    }

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::create_dir_all(root.join("node_modules/left-pad")).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();

        std::fs::write(root.join("letter.txt"), b"hello").unwrap();
        std::fs::write(root.join("docs/deed.pdf"), b"pdf bytes").unwrap();
        std::fs::write(root.join("node_modules/left-pad/index.js"), b"junk").unwrap();
        std::fs::write(
            root.join(".git/config"),
            b"[remote] url = https://token@host",
        )
        .unwrap();
        std::fs::write(root.join(".DS_Store"), b"junk").unwrap();

        dir
    }

    #[test]
    fn it_finds_real_files_in_a_stable_order() {
        let dir = tree();
        let w = walk(dir.path(), &[], true).unwrap();

        let paths: Vec<&str> = w.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["docs/deed.pdf", "letter.txt"]);
        assert_eq!(w.total_bytes, 5 + 9);

        let again = walk(dir.path(), &[], true).unwrap();
        assert_eq!(w.files, again.files);
    }

    #[test]
    fn dangerous_and_enormous_directories_are_excluded_by_default() {
        let dir = tree();
        let w = walk(dir.path(), &[], true).unwrap();

        let paths: Vec<&str> = w.files.iter().map(|f| f.path.as_str()).collect();
        assert!(
            !paths.iter().any(|p| p.contains(".git")),
            "a .git config was sealed"
        );
        assert!(!paths.iter().any(|p| p.contains("node_modules")));
        assert!(!paths.iter().any(|p| p.contains(".DS_Store")));
    }

    #[test]
    fn every_exclusion_is_reported() {
        let dir = tree();
        let w = walk(dir.path(), &[], true).unwrap();
        assert!(
            !w.skipped.is_empty(),
            "exclusions must be visible to the user"
        );
        assert!(w.skipped.iter().any(|(p, _)| p.contains(".git")));
    }

    #[test]
    fn defaults_can_be_turned_off() {
        let dir = tree();
        let w = walk(dir.path(), &[], false).unwrap();
        let paths: Vec<&str> = w.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.iter().any(|p| p.contains("node_modules")));
    }

    #[test]
    fn extra_patterns_are_honoured() {
        let dir = tree();
        let w = walk(dir.path(), &["**/*.pdf".to_string()], true).unwrap();
        let paths: Vec<&str> = w.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["letter.txt"]);
    }

    #[test]
    fn a_bad_pattern_is_reported_with_the_pattern_in_it() {
        let dir = tree();
        let err = walk(dir.path(), &["[".to_string()], true).unwrap_err();
        assert!(
            format!("{err}").contains('['),
            "the bad pattern should be named"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_followed() {
        let dir = tree();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("private.key"), b"very secret").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();

        let w = walk(dir.path(), &[], true).unwrap();
        assert!(
            !w.files.iter().any(|f| f.path.contains("private.key")),
            "a symlink pulled in a file from outside the folder"
        );
        assert!(w.skipped.iter().any(|(_, why)| why == "symbolic link"));
    }

    #[test]
    fn an_empty_folder_walks_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let w = walk(dir.path(), &[], true).unwrap();
        assert!(w.is_empty());
        assert_eq!(w.total_bytes, 0);
    }
}
