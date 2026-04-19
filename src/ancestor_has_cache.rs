use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const DEFAULT_TTL: Duration = Duration::from_secs(1);
const DEFAULT_NEGATIVE_DEPTH: usize = 10;
const DEFAULT_MAX_ENTRIES: usize = 16_384;

#[derive(Debug, Clone)]
struct CacheEntry {
    value: bool,
    expires_at: Instant,
}

#[derive(Debug)]
pub struct AncestorHasCache {
    ttl: Duration,
    negative_depth: usize,
    max_entries: usize,
    entries: papaya::HashMap<String, papaya::HashMap<PathBuf, CacheEntry>>,
    entry_count: AtomicUsize,
}

impl Default for AncestorHasCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_NEGATIVE_DEPTH)
    }
}

impl AncestorHasCache {
    pub fn new(ttl: Duration, negative_depth: usize) -> Self {
        Self::with_limits(ttl, negative_depth, DEFAULT_MAX_ENTRIES)
    }

    pub fn with_limits(ttl: Duration, negative_depth: usize, max_entries: usize) -> Self {
        Self {
            ttl,
            negative_depth,
            max_entries,
            entries: papaya::HashMap::new(),
            entry_count: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn negative_depth(&self) -> usize {
        self.negative_depth
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn max_entries(&self) -> usize {
        self.max_entries
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
                    if entry.value {
                        return Some(true);
                    }
                    // Negative entries are only safe to reuse for the exact
                    // queried parent directory. Reusing ancestor negatives for
                    // deeper paths can produce false negatives.
                    if dir == parent {
                        return Some(false);
                    }
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
        let replaced = per_name.pin().insert(path.to_path_buf(), entry).is_some();
        if !replaced {
            let size = self.entry_count.fetch_add(1, Ordering::Relaxed) + 1;
            if size > self.max_entries {
                names.clear();
                self.entry_count.store(0, Ordering::Relaxed);
            }
        }
    }

    #[cfg(test)]
    fn entry_count_for_test(&self) -> usize {
        self.entry_count.load(Ordering::Relaxed)
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
        let cache = AncestorHasCache::default();
        let now = t0();

        cache.record_positive(".git", Path::new("/repo"), now);

        assert_eq!(
            cache.lookup(".git", Path::new("/repo/src/main.rs"), now),
            Some(true)
        );
    }

    #[test]
    fn prefix_check_avoids_false_match_for_similar_paths() {
        let cache = AncestorHasCache::default();
        let now = t0();

        cache.record_positive(".git", Path::new("/a/b"), now);

        // `/a/bad/*` must not reuse `/a/b`.
        assert_eq!(cache.lookup(".git", Path::new("/a/bad/file"), now), None);
    }

    #[test]
    fn negative_cache_is_bounded_by_depth() {
        let cache = AncestorHasCache::new(Duration::from_secs(10), 2);
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
        let cache = AncestorHasCache::new(Duration::from_secs(1), 3);
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
        let cache = AncestorHasCache::new(Duration::from_secs(10), 3);
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
        let cache = AncestorHasCache::new(Duration::from_secs(10), 3);
        let now = t0();

        cache.record_positive(".marker", Path::new("/"), now);

        assert_eq!(
            cache.lookup(".marker", Path::new("/any/deep/path/file"), now),
            Some(true)
        );
    }

    #[test]
    fn clears_all_entries_when_size_exceeds_limit() {
        let cache = AncestorHasCache::with_limits(Duration::from_secs(10), 3, 2);
        let now = t0();

        cache.record_positive(".git", Path::new("/repo/a"), now);
        cache.record_positive(".git", Path::new("/repo/b"), now);
        assert_eq!(cache.entry_count_for_test(), 2);

        // third unique insert exceeds max_entries and clears all cached entries.
        cache.record_positive(".git", Path::new("/repo/c"), now);
        assert_eq!(cache.entry_count_for_test(), 0);
        assert_eq!(cache.lookup(".git", Path::new("/repo/a/file"), now), None);
        assert_eq!(cache.lookup(".git", Path::new("/repo/b/file"), now), None);
        assert_eq!(cache.lookup(".git", Path::new("/repo/c/file"), now), None);
    }

    #[test]
    fn ancestor_negative_is_not_reused_for_deeper_parent() {
        let cache = AncestorHasCache::new(Duration::from_secs(10), 3);
        let now = t0();

        cache.record_negative(".git", Path::new("/a/b"), now);
        assert_eq!(
            cache.lookup(".git", Path::new("/a/b/c/file.txt"), now),
            None
        );
    }
}
