use commonware_cryptography::{sha256::Digest, Sha256};

use crate::mmr::hasher::{Hasher, Standard};

type Hash32 = [u8; 32];

/// A compact MMR that stores only its current set of peaks and the number of inserted leaves.
///
/// - `len`: number of leaves inserted so far.
/// - `peaks`: the current peaks as pairs of (post-order position, digest).
/// - `hasher`: pluggable hashing used for leaf, inner-node, and root hashing.
pub struct PeaksMMR {
    len: u64,
    peaks: Vec<(u64, Digest)>,
    hasher: Standard<Sha256>,
}

impl PeaksMMR {
    /// Construct an MMR from existing peaks and reserve for upcoming insertions.
    ///
    /// `initial_peaks` are pairs of (post-order position, 32-byte hash). The number of existing
    /// leaves is inferred from the last peak's position using `flat_idx_to_leaf_idx`.
    /// `add_count` is a hint used to pre-allocate peak capacity.
    pub fn new(initial_peaks: Vec<(u64, Hash32)>, add_count: usize) -> Self {
        let len = if let Some(last) = initial_peaks.last() {
            flat_idx_to_leaf_idx(last.0 + 1)
        } else {
            0
        };

        let hasher: Standard<Sha256> = Standard::default();

        let max_len = len + add_count as u64;
        assert!(max_len != 0);

        // Reserve up to max number of peaks: max_peaks_len = ⌊log₂(max_len)⌋ + 1
        let max_peaks_len = (64 - max_len.leading_zeros()) as usize;

        let mut peaks = Vec::with_capacity(max_peaks_len);
        for (i, h) in initial_peaks {
            peaks.push((i, Digest(h.as_ref().try_into().unwrap())));
        }

        PeaksMMR { len, peaks, hasher }
    }

    /// Append a new leaf (32-byte hash) and update peaks by merging as long as possible.
    pub fn add(&mut self, hash: &Hash32) {
        let flat_index = if let Some(last) = self.peaks.last() {
            last.0 + 1
        } else {
            0
        };
        self.peaks.push((
            flat_index,
            self.hasher.leaf_digest(flat_index, hash.as_ref()),
        ));

        let leaf_index = self.len;
        self.len += 1;

        // Merge as many times as allowed by the number of trailing ones in the current leaf index.
        for i in 0..leaf_index.trailing_ones() {
            let right = self.peaks.pop().unwrap();
            let left = self.peaks.pop().unwrap();

            // For a perfect tree of height `i`, adjacent subtree roots are separated by
            // stride = 2^(i+1) − 1 in post-order positions.
            let stride = (1 << (i + 1)) - 1;
            assert_eq!(left.0 + stride, right.0);

            let parent_index = right.0 + 1;
            let hash = self.hasher.node_digest(parent_index, &left.1, &right.1);
            self.peaks.push((parent_index, hash));
        }
    }

    /// Compute the MMR root as a digest of the MMR size and the ordered peak digests.
    pub fn root(&mut self) -> Digest {
        if self.peaks.is_empty() {
            return Digest([0u8; 32]);
        }

        // mmr_size(n) = 2n − popcount(n)
        let size = 2 * self.len - self.len.count_ones() as u64;
        let hash = self.hasher.root(size, self.peaks.iter().map(|(_, h)| h));
        hash
    }
}

/// Convert a post-order flat index to its corresponding leaf index.
///
/// In a post-order indexed MMR, the position of the n-th leaf (0-based) is:
/// `p(n) = 2n - popcount(n)`. This inverts `p(n)` via binary search to recover `n` for a given
/// leaf position.
fn flat_idx_to_leaf_idx(flat_index: u64) -> u64 {
    let mut lo = 0u64;
    let mut hi = flat_index; // p(n) >= n, so n <= flat_index

    while lo <= hi {
        let mid = (lo + hi) / 2;
        let pos = 2 * mid - (mid.count_ones() as u64);
        if pos == flat_index {
            return mid;
        } else if pos < flat_index {
            lo = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }

    panic!("flat_index {} is not a leaf position", flat_index);
}

#[cfg(test)]
mod tests {
    use commonware_cryptography::Sha256;

    use crate::mmr::{hasher::Standard, mem::Mmr, tests::peaksmmr::PeaksMMR};

    #[test]
    fn test_consistency() {
        let mut mmr0 = Mmr::new();
        let mut hasher: Standard<Sha256> = Standard::default();

        let mut mmr1 = PeaksMMR::new(vec![], 10000);

        for i in 0..10000u64 {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(i.to_be_bytes().as_ref());
            mmr0.add(&mut hasher, &hash);
            let root0 = mmr0.root(&mut hasher);

            mmr1.add(&hash);
            let root1 = mmr1.root();

            assert_eq!(root0, root1);
        }
    }
}
