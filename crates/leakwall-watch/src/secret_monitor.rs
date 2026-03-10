use std::io::BufRead;
use std::path::Path;

use crate::WatchError;

/// Count non-empty, non-comment lines in a secret file (e.g. `.env`).
/// Lines that are blank or start with `#` are excluded.
pub fn count_secrets_in_file(path: &Path) -> Result<usize, WatchError> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);

    let count = reader
        .lines()
        .map_while(Result::ok)
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .count();

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_count_secrets_basic() {
        let mut tmp = NamedTempFile::new().expect("create temp file");
        writeln!(tmp, "# comment").expect("write");
        writeln!(tmp, "API_KEY=secret123").expect("write");
        writeln!(tmp).expect("write");
        writeln!(tmp, "DB_PASS=hunter2").expect("write");
        writeln!(tmp, "  # another comment").expect("write");
        tmp.flush().expect("flush");

        let count = count_secrets_in_file(tmp.path()).expect("count");
        assert_eq!(count, 2);
    }

    #[test]
    fn test_count_secrets_empty_file() {
        let tmp = NamedTempFile::new().expect("create temp file");
        let count = count_secrets_in_file(tmp.path()).expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_count_secrets_all_comments() {
        let mut tmp = NamedTempFile::new().expect("create temp file");
        writeln!(tmp, "# comment 1").expect("write");
        writeln!(tmp, "# comment 2").expect("write");
        tmp.flush().expect("flush");

        let count = count_secrets_in_file(tmp.path()).expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_count_secrets_nonexistent_file() {
        let result = count_secrets_in_file(Path::new("/tmp/leakwall_no_such_file_abc123"));
        assert!(result.is_err());
    }
}
