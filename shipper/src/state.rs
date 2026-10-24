use std::fs::{self, File};
use std::os::unix::fs::FileExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Сколько первых байт файла участвует в отпечатке.
pub const HEAD_LEN: u64 = 256;

/// Позиция чтения в alerts.json. Inode ловит ротацию; отпечаток начала файла
/// ловит переиспользование inode (файл удалён, новый получил тот же номер и
/// вырос больше сохранённого смещения — по одному inode это неотличимо).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub inode: u64,
    pub offset: u64,
    /// Длина префикса, по которому посчитан head_hash (0 — отпечатка нет).
    #[serde(default)]
    pub head_len: u64,
    #[serde(default)]
    pub head_hash: u64,
}

/// FNV-1a 64: детерминирован между версиями Rust, в отличие от DefaultHasher.
pub fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// Отпечаток первых `min(HEAD_LEN, len)` байт файла: (длина, хеш).
/// Читает через pread — позиция открытого файла не меняется.
pub fn head_fingerprint(file: &File) -> std::io::Result<(u64, u64)> {
    let len = file.metadata()?.len().min(HEAD_LEN);
    let mut buf = vec![0u8; len as usize];
    let mut read = 0;
    while read < buf.len() {
        let n = file.read_at(&mut buf[read..], read as u64)?;
        if n == 0 {
            break;
        }
        read += n;
    }
    buf.truncate(read);
    Ok((read as u64, fnv1a(&buf)))
}

/// Сходится ли начало файла с сохранённым отпечатком. Без отпечатка в
/// чекпоинте (старый формат или пустой файл) — считаем, что сходится.
pub fn head_matches(file: &File, cp: Checkpoint) -> std::io::Result<bool> {
    if cp.head_len == 0 {
        return Ok(true);
    }
    let mut buf = vec![0u8; cp.head_len as usize];
    let mut read = 0;
    while read < buf.len() {
        let n = file.read_at(&mut buf[read..], read as u64)?;
        if n == 0 {
            break;
        }
        read += n;
    }
    if read as u64 != cp.head_len {
        return Ok(false);
    }
    Ok(fnv1a(&buf) == cp.head_hash)
}

pub fn load(path: &Path) -> Checkpoint {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save(path: &Path, cp: Checkpoint) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec(&cp)?)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("shipper-state-{}-{name}", std::process::id()))
    }

    #[test]
    fn fnv1a_is_deterministic_and_sensitive() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"abc"), fnv1a(b"abc"));
        assert_ne!(fnv1a(b"abc"), fnv1a(b"abd"));
    }

    #[test]
    fn fingerprint_covers_at_most_head_len_bytes() {
        let p = tmp("fp.log");
        fs::write(&p, vec![b'a'; 1000]).unwrap();
        let f = File::open(&p).unwrap();
        let (len, hash) = head_fingerprint(&f).unwrap();
        assert_eq!(len, HEAD_LEN);
        assert_eq!(hash, fnv1a(&vec![b'a'; HEAD_LEN as usize]));

        fs::write(&p, b"short").unwrap();
        let f = File::open(&p).unwrap();
        assert_eq!(head_fingerprint(&f).unwrap(), (5, fnv1a(b"short")));
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn head_matches_detects_replaced_content_and_tolerates_growth() {
        let p = tmp("hm.log");
        fs::write(&p, b"line-one\n").unwrap();
        let f = File::open(&p).unwrap();
        let (head_len, head_hash) = head_fingerprint(&f).unwrap();
        let cp = Checkpoint {
            inode: 1,
            offset: 9,
            head_len,
            head_hash,
        };

        // Файл дописан — префикс тот же, отпечаток сходится.
        fs::write(&p, b"line-one\nline-two\n").unwrap();
        assert!(head_matches(&File::open(&p).unwrap(), cp).unwrap());

        // Тот же размер и больше, но другое начало — не сходится.
        fs::write(&p, b"LINE-ONE\nline-two\n").unwrap();
        assert!(!head_matches(&File::open(&p).unwrap(), cp).unwrap());

        // Файл короче отпечатка — не сходится.
        fs::write(&p, b"li").unwrap();
        assert!(!head_matches(&File::open(&p).unwrap(), cp).unwrap());

        // Чекпоинт без отпечатка — совместимость: всегда сходится.
        let legacy = Checkpoint {
            inode: 1,
            offset: 9,
            ..Default::default()
        };
        assert!(head_matches(&File::open(&p).unwrap(), legacy).unwrap());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn legacy_checkpoint_json_loads_with_zero_fingerprint() {
        let p = tmp("legacy.json");
        fs::write(&p, br#"{"inode":42,"offset":1000}"#).unwrap();
        let cp = load(&p);
        assert_eq!(
            cp,
            Checkpoint {
                inode: 42,
                offset: 1000,
                head_len: 0,
                head_hash: 0
            }
        );
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn save_then_load_roundtrip() {
        let p = tmp("rt/shipper.json");
        let cp = Checkpoint {
            inode: 7,
            offset: 99,
            head_len: 12,
            head_hash: 0xdead,
        };
        save(&p, cp).unwrap();
        assert_eq!(load(&p), cp);
        let _ = fs::remove_dir_all(p.parent().unwrap());
    }
}
