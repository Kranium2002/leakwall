use std::path::Path;

use crate::FileChange;

/// Classify a skill file change based on the path and whether the
/// file existed before the event.
pub fn classify_skill_change(path: &Path, existed_before: bool) -> FileChange {
    if !path.exists() {
        FileChange::Deleted
    } else if existed_before {
        FileChange::Modified
    } else {
        FileChange::Created
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_classify_created() {
        let tmp = NamedTempFile::new().expect("create temp file");
        let change = classify_skill_change(tmp.path(), false);
        assert!(matches!(change, FileChange::Created));
    }

    #[test]
    fn test_classify_modified() {
        let tmp = NamedTempFile::new().expect("create temp file");
        let change = classify_skill_change(tmp.path(), true);
        assert!(matches!(change, FileChange::Modified));
    }

    #[test]
    fn test_classify_deleted() {
        let path = Path::new("/tmp/leakwall_nonexistent_skill_file_xyz");
        let change = classify_skill_change(path, true);
        assert!(matches!(change, FileChange::Deleted));
    }
}
