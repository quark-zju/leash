use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const DEFAULT_TTL: Duration = Duration::from_secs(1);
const DEFAULT_NEGATIVE_DEPTH: usize = 3;

#[derive(Debug, Clone)]
struct CacheEntry {
    value: bool,
    expires_at: Instant,
}

#[derive(Debug)]
pub struct AncestorHasCache {
    ttl: Duration,
    negative_depth: usize,
    entries: papaya::HashMap<String, papaya::HashMap<PathBuf, CacheEntry>>,
}

impl Default for AncestorHasCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_NEGATIVE_DEPTH)
    }
}

impl AncestorHasCache {
    pub fn new(ttl: Duration, negative_depth: usize) -> Self {
        Self {
            ttl,
            negative_depth,
            entries: papaya::HashMap::new(),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn negative_depth(&self) -> usize {
        self.negative_depth
    }

    /// Looks up a cached ancestor-has decision for `path`.
    ///
    /// Returns:
    /// - `Some(true)` when a cached positive ancestor is found.
    /// - `Some(false)` when a cached negative ancestor (within configured depth)
    ///   is found.
    /// - `None` when no usable cache entry exists.
    pub fn lookup(&self, name: &str, path: &Path, now: Instant) -> Option<bool> {
        let parent = path.parent()?;
        let names = self.entries.pin();
        let per_name = names.get(name)?;
        let per_name = per_name.pin();

        let mut current = Some(parent);
        while let Some(dir) = current {
            if let Some(entry) = per_name.get(dir) {
                if entry.expires_at > now {
                    return Some(entry.value);
                }
            }
            current = dir.parent();
        }
        None
    }

    /// Records that `<ancestor>/<name>` exists.
    pub fn record_positive(&self, name: &str, ancestor: &Path, now: Instant) {
        self.insert(name, ancestor, true, now);
    }

    /// Records a bounded negative cache from `start_dir` upwards.
    ///
    /// When `negative_depth = 3`, this records:
    /// - `start_dir`
    /// - `start_dir.parent()`
    /// - `start_dir.parent().parent()`
    pub fn record_negative(&self, name: &str, start_dir: &Path, now: Instant) {
        if self.negative_depth == 0 {
            return;
        }

        let mut current = Some(start_dir);
        for _ in 0..self.negative_depth {
            let Some(dir) = current else {
                break;
            };
            self.insert(name, dir, false, now);
            current = dir.parent();
        }
    }

    fn insert(&self, name: &str, path: &Path, value: bool, now: Instant) {
        let expires_at = now + self.ttl;
        let entry = CacheEntry { value, expires_at };
        let names = self.entries.pin();
        let per_name = names.get_or_insert_with(name.to_owned(), papaya::HashMap::new);
        per_name.pin().insert(path.to_path_buf(), entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn positive_cache_matches_descendant_lookup() {
        let mut cache = AncestorHasCache::default();
        let now = t0();

        cache.record_positive(".git", Path::new("/repo"), now);

        assert_eq!(
            cache.lookup(".git", Path::new("/repo/src/main.rs"), now),
            Some(true)
        );
    }

    #[test]
    fn prefix_check_avoids_false_match_for_similar_paths() {
        let mut cache = AncestorHasCache::default();
        let now = t0();

        cache.record_positive(".git", Path::new("/a/b"), now);

        // `/a/bad/*` must not reuse `/a/b`.
        assert_eq!(cache.lookup(".git", Path::new("/a/bad/file"), now), None);
    }

    #[test]
    fn negative_cache_is_bounded_by_depth() {
        let mut cache = AncestorHasCache::new(Duration::from_secs(10), 2);
        let now = t0();

        cache.record_negative(".git", Path::new("/a/b/c"), now);

        // cached: /a/b/c (for /a/b/c/*), /a/b (for /a/b/*)
        assert_eq!(
            cache.lookup(".git", Path::new("/a/b/c/d"), now),
            Some(false)
        );
        assert_eq!(cache.lookup(".git", Path::new("/a/b/x"), now), Some(false));

        // not cached due to depth limit (would need /a)
        assert_eq!(cache.lookup(".git", Path::new("/a/z"), now), None);
    }

    #[test]
    fn ttl_expiry_discards_entries() {
        let mut cache = AncestorHasCache::new(Duration::from_secs(1), 3);
        let now = t0();

        cache.record_positive(".git", Path::new("/repo"), now);
        assert_eq!(
            cache.lookup(".git", Path::new("/repo/src/main.rs"), now),
            Some(true)
        );

        let expired = now + Duration::from_millis(1001);
        assert_eq!(
            cache.lookup(".git", Path::new("/repo/src/main.rs"), expired),
            None
        );
    }

    #[test]
    fn lookup_prefers_deepest_non_expired_ancestor() {
        let mut cache = AncestorHasCache::new(Duration::from_secs(10), 3);
        let now = t0();

        cache.record_positive(".git", Path::new("/repo"), now);
        cache.record_negative(".git", Path::new("/repo/src"), now);

        // Deepest ancestor wins, so this uses negative at /repo/src.
        assert_eq!(
            cache.lookup(".git", Path::new("/repo/src/main.rs"), now),
            Some(false)
        );
    }

    #[test]
    fn root_ancestor_entry_can_match_any_absolute_descendant() {
        let mut cache = AncestorHasCache::new(Duration::from_secs(10), 3);
        let now = t0();

        cache.record_positive(".marker", Path::new("/"), now);

        assert_eq!(
            cache.lookup(".marker", Path::new("/any/deep/path/file"), now),
            Some(true)
        );
    }
}
