use smallvec::SmallVec;

/// Sparse-grow bitset with inline storage for 8 words.
///
/// - Each word stores 64 bits.
/// - Inline capacity: 8 words (`512` bits) before spilling to heap.
/// - Growth is on-demand only; no full pre-allocation by rule count.
#[derive(Debug, Default, Clone)]
pub struct SparseBitset {
    words: SmallVec<[u64; 8]>,
}

impl SparseBitset {
    pub fn set(&mut self, bit: usize) {
        let (word_index, mask) = split_bit(bit);
        if self.words.len() <= word_index {
            self.words.resize(word_index + 1, 0);
        }
        self.words[word_index] |= mask;
    }

    pub fn clear(&mut self, bit: usize) {
        let (word_index, mask) = split_bit(bit);
        let Some(word) = self.words.get_mut(word_index) else {
            return;
        };
        *word &= !mask;
        while self.words.last().is_some_and(|word| *word == 0) {
            self.words.pop();
        }
    }

    pub fn test(&self, bit: usize) -> bool {
        let (word_index, mask) = split_bit(bit);
        self.words
            .get(word_index)
            .is_some_and(|word| (*word & mask) != 0)
    }
}

fn split_bit(bit: usize) -> (usize, u64) {
    (bit / 64, 1_u64 << (bit % 64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_test_inline_bits() {
        let mut bits = SparseBitset::default();
        assert!(!bits.test(0));
        assert!(!bits.test(255));

        bits.set(0);
        bits.set(255);

        assert!(bits.test(0));
        assert!(bits.test(255));
        assert!(!bits.test(254));
    }

    #[test]
    fn set_and_test_heap_spill_bits() {
        let mut bits = SparseBitset::default();
        bits.set(700);
        assert!(bits.test(700));
        assert!(!bits.test(699));
    }

    #[test]
    fn clear_unset_bit_is_noop() {
        let mut bits = SparseBitset::default();
        bits.clear(42);
        assert!(!bits.test(42));
    }

    #[test]
    fn clear_removes_high_zero_words() {
        let mut bits = SparseBitset::default();
        bits.set(700);
        bits.clear(700);
        assert!(!bits.test(700));
    }

    #[test]
    fn clear_selected_bits_preserves_others() {
        let mut bits = SparseBitset::default();
        bits.set(5);
        bits.set(130);
        bits.clear(5);
        assert!(!bits.test(5));
        assert!(bits.test(130));
        bits.clear(130);
        assert!(!bits.test(5));
        assert!(!bits.test(130));
    }
}
