use std::hash::Hasher;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use fs_err as fs;
use serde::Serialize;
use twox_hash::XxHash64;

pub const HEADER_LEN: usize = 17;
pub const TAG_WRITE_OP: u8 = 0x01;
pub const FLUSHED_BIT: u8 = 0x80;
pub const AUTO_FLUSH_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub offset: u64,
    pub tag: u8,
    pub flushed: bool,
    pub payload: Vec<u8>,
}

pub struct Writer {
    inner: Arc<Mutex<WriterInner>>,
    shutdown: Arc<AtomicBool>,
    flusher_thread: thread::Thread,
    flusher_join: Option<thread::JoinHandle<()>>,
}

struct WriterInner {
    buf: BufWriter<fs::File>,
    next_offset: u64,
    dirty: bool,
    last_write: Option<Instant>,
    background_error: Option<String>,
}

impl Writer {
    pub fn open_append(path: &Path) -> Result<Self> {
        let file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| {
                format!("failed to open record file for append: {}", path.display())
            })?;
        let next_offset = file
            .metadata()
            .with_context(|| format!("failed to stat record file: {}", path.display()))?
            .len();
        let inner = Arc::new(Mutex::new(WriterInner {
            buf: BufWriter::new(file),
            next_offset,
            dirty: false,
            last_write: None,
            background_error: None,
        }));
        let shutdown = Arc::new(AtomicBool::new(false));

        let flusher_join = spawn_flusher(Arc::downgrade(&inner), shutdown.clone());
        let flusher_thread = flusher_join.thread().clone();
        Ok(Self {
            inner,
            shutdown,
            flusher_thread,
            flusher_join: Some(flusher_join),
        })
    }

    pub fn append_cbor<T: Serialize>(&self, tag: u8, value: &T) -> Result<u64> {
        let payload = serde_cbor::to_vec(value).context("failed to encode cbor payload")?;
        self.append_payload(tag, &payload)
    }

    pub fn append_payload(&self, tag: u8, payload: &[u8]) -> Result<u64> {
        if tag & FLUSHED_BIT != 0 {
            bail!("invalid record tag {tag:#x}: high bit is reserved for flush marker");
        }
        let mut inner = self.lock_inner()?;
        if let Some(err) = inner.background_error.take() {
            bail!("background record flush failed previously: {err}");
        }

        let len = payload.len() as u64;
        let checksum = checksum64(payload);
        let mut header = [0u8; HEADER_LEN];
        header[0] = tag;
        header[1..9].copy_from_slice(&len.to_le_bytes());
        header[9..17].copy_from_slice(&checksum.to_le_bytes());

        let offset = inner.next_offset;
        inner
            .buf
            .write_all(&header)
            .context("failed to write record header")?;
        inner
            .buf
            .write_all(payload)
            .context("failed to write record payload")?;
        inner.next_offset += HEADER_LEN as u64 + len;
        inner.dirty = true;
        inner.last_write = Some(Instant::now());
        self.flusher_thread.unpark();
        Ok(offset)
    }

    pub fn sync(&self) -> Result<()> {
        let mut inner = self.lock_inner()?;
        if let Some(err) = inner.background_error.take() {
            bail!("background record flush failed previously: {err}");
        }
        flush_inner(&mut inner, true)
    }

    fn lock_inner(&self) -> Result<std::sync::MutexGuard<'_, WriterInner>> {
        self.inner
            .lock()
            .map_err(|_| anyhow::anyhow!("record writer mutex poisoned"))
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            let _ = flush_inner(&mut inner, true);
        }
        self.shutdown.store(true, Ordering::Relaxed);
        self.flusher_thread.unpark();
        if let Some(join) = self.flusher_join.take() {
            let _ = join.join();
        }
    }
}

fn spawn_flusher(
    inner: Weak<Mutex<WriterInner>>,
    shutdown: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            thread::park_timeout(AUTO_FLUSH_INTERVAL);
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            let Some(shared) = inner.upgrade() else {
                break;
            };
            let mut guard = match shared.lock() {
                Ok(guard) => guard,
                Err(_) => break,
            };
            if !guard.dirty {
                continue;
            }
            let should_flush = guard
                .last_write
                .is_some_and(|last| last.elapsed() >= AUTO_FLUSH_INTERVAL);
            if !should_flush {
                continue;
            }
            if let Err(err) = flush_inner(&mut guard, false) {
                guard.background_error = Some(format!("{err:#}"));
            }
        }
    })
}

fn flush_inner(inner: &mut WriterInner, sync_data: bool) -> Result<()> {
    if !inner.dirty {
        if sync_data {
            inner
                .buf
                .get_ref()
                .sync_data()
                .context("failed to sync record file data")?;
        }
        return Ok(());
    }

    inner
        .buf
        .flush()
        .context("failed to flush buffered record writes")?;
    if sync_data {
        inner
            .buf
            .get_ref()
            .sync_data()
            .context("failed to sync record file data")?;
    }
    inner.dirty = false;
    Ok(())
}

pub fn read_frames(path: &Path) -> Result<Vec<Frame>> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to read record file: {}", path.display()));
        }
    };

    Ok(read_frames_from_bytes(&data))
}

fn read_frames_from_bytes(data: &[u8]) -> Vec<Frame> {
    let mut frames = Vec::new();
    let mut cursor: usize = 0;

    while cursor < data.len() {
        if data.len() - cursor < HEADER_LEN {
            break;
        }

        let raw_tag = data[cursor];
        let tag = raw_tag & !FLUSHED_BIT;
        let flushed = raw_tag & FLUSHED_BIT != 0;
        let len = u64::from_le_bytes(data[cursor + 1..cursor + 9].try_into().unwrap()) as usize;
        let expected_checksum =
            u64::from_le_bytes(data[cursor + 9..cursor + 17].try_into().unwrap());
        cursor += HEADER_LEN;

        if data.len() - cursor < len {
            break;
        }

        let payload = &data[cursor..cursor + len];
        if checksum64(payload) != expected_checksum {
            break;
        }

        frames.push(Frame {
            offset: (cursor - HEADER_LEN) as u64,
            tag,
            flushed,
            payload: payload.to_vec(),
        });
        cursor += len;
    }

    frames
}

fn checksum64(data: &[u8]) -> u64 {
    let mut hasher = XxHash64::default();
    hasher.write(data);
    hasher.finish()
}

pub fn decode_cbor<T: serde::de::DeserializeOwned>(frame: &Frame) -> Result<T> {
    serde_cbor::from_slice(&frame.payload).context("failed to decode cbor payload")
}

pub fn mark_flushed(path: &Path, offset: u64) -> Result<bool> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| {
            format!(
                "failed to open record file for mark_flushed: {}",
                path.display()
            )
        })?;

    file.seek(SeekFrom::Start(offset)).with_context(|| {
        format!(
            "failed to seek to record offset {} in {}",
            offset,
            path.display()
        )
    })?;

    let mut tag = [0u8; 1];
    file.read_exact(&mut tag).with_context(|| {
        format!(
            "failed to read record tag at {} in {}",
            offset,
            path.display()
        )
    })?;
    if tag[0] & FLUSHED_BIT != 0 {
        return Ok(false);
    }

    tag[0] |= FLUSHED_BIT;
    file.seek(SeekFrom::Start(offset)).with_context(|| {
        format!(
            "failed to seek to rewrite tag at {} in {}",
            offset,
            path.display()
        )
    })?;
    file.write_all(&tag)
        .with_context(|| format!("failed to rewrite tag at {} in {}", offset, path.display()))?;
    file.sync_data().with_context(|| {
        format!(
            "failed to sync record file after mark_flushed: {}",
            path.display()
        )
    })?;
    Ok(true)
}

pub fn truncate_tail(path: &Path, keep_len: u64) -> Result<()> {
    let file = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| {
            format!(
                "failed to open record file for truncate: {}",
                path.display()
            )
        })?;
    file.set_len(keep_len)
        .with_context(|| format!("failed to truncate record file: {}", path.display()))
}

pub fn corrupt_byte(path: &Path, offset: u64, value: u8) -> Result<()> {
    let mut data = fs::read(path).with_context(|| {
        format!(
            "failed to read record file for corruption: {}",
            path.display()
        )
    })?;
    if (offset as usize) < data.len() {
        data[offset as usize] = value;
    }
    fs::write(path, data).with_context(|| {
        format!(
            "failed to rewrite corrupted record file: {}",
            path.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_record_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        p.push(format!("cowjail-{name}-{now}.cjr"));
        p
    }

    #[test]
    fn write_then_read_roundtrip() {
        let path = temp_record_path("roundtrip");
        let writer = Writer::open_append(&path).expect("writer open");
        writer
            .append_cbor(TAG_WRITE_OP, &("path", 7u32))
            .expect("append");
        writer.sync().expect("sync");

        let frames = read_frames(&path).expect("read frames");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].tag, TAG_WRITE_OP);
        assert!(!frames[0].flushed);
        let payload: (String, u32) = decode_cbor(&frames[0]).expect("decode payload");
        assert_eq!(payload.0, "path");
        assert_eq!(payload.1, 7);
    }

    #[test]
    fn partial_tail_is_ignored() {
        let path = temp_record_path("partial");
        let writer = Writer::open_append(&path).expect("writer open");
        writer.append_cbor(TAG_WRITE_OP, &1u32).expect("append 1");
        let second_offset = writer.append_cbor(TAG_WRITE_OP, &2u32).expect("append 2");
        writer.sync().expect("sync");

        truncate_tail(&path, second_offset + 5).expect("truncate");
        let frames = read_frames(&path).expect("read frames");
        assert_eq!(frames.len(), 1);
        let v: u32 = decode_cbor(&frames[0]).expect("decode value");
        assert_eq!(v, 1);
    }

    #[test]
    fn checksum_failure_stops_iteration() {
        let path = temp_record_path("checksum");
        let writer = Writer::open_append(&path).expect("writer open");
        writer.append_cbor(TAG_WRITE_OP, &1u32).expect("append 1");
        let second_offset = writer.append_cbor(TAG_WRITE_OP, &2u32).expect("append 2");
        writer.sync().expect("sync");

        corrupt_byte(&path, second_offset + HEADER_LEN as u64, 0xFF).expect("corrupt");
        let frames = read_frames(&path).expect("read frames");
        assert_eq!(frames.len(), 1);
        let v: u32 = decode_cbor(&frames[0]).expect("decode value");
        assert_eq!(v, 1);
    }

    #[test]
    fn mark_flushed_is_idempotent() {
        let path = temp_record_path("mark-flushed");
        let writer = Writer::open_append(&path).expect("writer open");
        let offset = writer.append_cbor(TAG_WRITE_OP, &123u32).expect("append");
        writer.sync().expect("sync");

        assert!(mark_flushed(&path, offset).expect("first mark"));
        assert!(!mark_flushed(&path, offset).expect("second mark"));

        let frames = read_frames(&path).expect("read frames");
        assert_eq!(frames.len(), 1);
        assert!(frames[0].flushed);
    }
}
