//! Runtime-switchable diagnostic log shared by every consumer of the library.
//!
//! Logging is off by default. When enabled, lines are appended to a log file
//! (and echoed to stderr); the file is rotated to `<name>.1` once it grows past
//! [`MAX_LOG_BYTES`], so leaving logging on cannot fill the disk.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

static ENABLED: AtomicBool = AtomicBool::new(false);
static SINK: Mutex<Option<Sink>> = Mutex::new(None);

struct Sink {
    file: File,
    size: u64,
}

/// Turns diagnostic logging on or off for the whole process.
pub fn set_verbose_logging(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
    if !enabled {
        *lock_sink() = None;
    }
}

pub fn verbose_logging_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Location of the log file this process writes to.
pub fn log_file_path() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("NulConnect").join("NulConnect.log")
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME")
            .filter(|home| home != "/var/root")
            .map(|home| {
                PathBuf::from(home).join("Library/Application Support/NulConnect/NulConnect.log")
            })
            .unwrap_or_else(|| {
                PathBuf::from("/Library/Application Support/NulConnect/nulconnect-helper.log")
            })
    }
}

/// Appends one timestamped line to the log when logging is enabled.
pub fn log_write(message: &str) {
    if !verbose_logging_enabled() {
        return;
    }
    let line = format!("[{}] {message}\n", timestamp());
    eprint!("{line}");

    append_line(&mut lock_sink(), &log_file_path(), &line, MAX_LOG_BYTES);
}

fn append_line(slot: &mut Option<Sink>, path: &Path, line: &str, max_bytes: u64) {
    if slot.is_none() {
        *slot = open_sink(path);
    }
    let Some(sink) = slot.as_ref() else { return };
    if sink.size > 0 && sink.size + line.len() as u64 > max_bytes {
        let mut backup = path.as_os_str().to_owned();
        backup.push(".1");
        *slot = None;
        let _ = std::fs::rename(path, backup);
        *slot = open_sink(path);
    }
    if let Some(sink) = slot.as_mut()
        && sink.file.write_all(line.as_bytes()).is_ok()
    {
        sink.size += line.len() as u64;
    }
}

fn lock_sink() -> std::sync::MutexGuard<'static, Option<Sink>> {
    SINK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn open_sink(path: &Path) -> Option<Sink> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    Some(Sink { file, size })
}

/// UTC time as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        now.subsec_millis()
    )
}

/// Formats and logs a message only when logging is enabled, so disabled
/// logging costs one atomic load and no string formatting.
macro_rules! diag_log {
    ($($arg:tt)*) => {
        if $crate::verbose_logging_enabled() {
            $crate::log_write(&format!($($arg)*));
        }
    };
}
pub(crate) use diag_log;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_to_backup_when_the_limit_is_exceeded() {
        let dir = std::env::temp_dir().join(format!("atr-log-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.log");
        let mut slot = None;
        for i in 0..10 {
            append_line(&mut slot, &path, &format!("line {i:02}\n"), 30);
        }
        let current = std::fs::read_to_string(&path).unwrap();
        let backup = std::fs::read_to_string(dir.join("test.log.1")).unwrap();
        assert!(current.len() <= 30 && backup.len() <= 30);
        assert!(current.contains("line 09"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn timestamp_has_iso_shape() {
        let ts = timestamp();
        assert_eq!(ts.len(), 24, "{ts}");
        assert!(ts.starts_with("20") && ts.ends_with('Z'));
    }
}
