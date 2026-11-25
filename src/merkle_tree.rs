//! Poseidon Merkle commitments to registered verification keys and lottery targets.
//!
//! Leaves hash the three fields `(vk_x, vk_y, target)`. Internal nodes hash
//! `(left, right)`, and missing children use `Poseidon([0])`. Paths list
//! siblings from the leaf upward, matching the certificate verification gadget.

use crate::{HashCPU, JubjubBase, PoseidonHash, Target, schnorr_signature::VerificationKey};
use ff::Field;

type F = JubjubBase;

/// Registry entry pairing a verification key with its inclusive lottery target.
#[derive(Debug, Copy, Clone)]
pub struct MTLeaf(pub VerificationKey, pub Target);

impl MTLeaf {
    /// Encodes the leaf as `(vk_x, vk_y, target)` before hashing.
    pub fn to_field(&self) -> [F; 3] {
        let mut elements = [F::ZERO; 3];
        elements[0..2].copy_from_slice(&self.0.to_field());
        elements[2] = self.1;
        elements
    }
}

/// Position of a sibling relative to the current node in a membership path.
#[derive(Clone, Copy, Debug)]
pub enum Position {
    /// Hash the sibling before the current node; encoded as field zero.
    Left,
    /// Hash the current node before the sibling; encoded as field one.
    Right,
}

impl From<Position> for F {
    fn from(value: Position) -> Self {
        match value {
            Position::Left => F::ZERO,
            Position::Right => F::ONE,
        }
    }
}

/// Membership-path siblings and their positions, ordered from the leaf upward.
#[derive(Clone, Debug)]
pub struct MerklePath {
    /// Each pair contains a sibling's position and its hash.
    pub siblings: Vec<(Position, F)>,
}

impl MerklePath {
    /// Wraps an ordered list of siblings without validating a root or depth.
    pub fn new(siblings: Vec<(Position, F)>) -> Self {
        Self { siblings }
    }

    /// Borrows the leaf-to-root sequence of siblings.
    pub fn get_siblings(&self) -> &[(Position, F)] {
        &self.siblings
    }

    /// Recomputes a root from a leaf and this path, outside the circuit.
    ///
    /// Membership is established by comparing the result with the expected
    /// registry root; this method does not perform that comparison itself.
    pub fn compute_root(&self, leaf: MTLeaf) -> F {
        let digest = PoseidonHash::hash(&leaf.to_field());

        // Compute the Merkle root.
        self.siblings.iter().fold(digest, |acc, x| match x.0 {
            // If the sibling is on the left, hash (sibling, node).
            Position::Left => PoseidonHash::hash(&[x.1, acc]),
            // If the sibling is on the right, hash (node, sibling).
            Position::Right => PoseidonHash::hash(&[acc, x.1]),
        })
    }
}

/// Poseidon tree stored as a binary heap, with leaves at a common depth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    /// The nodes are stored in an array heap:
    /// * `nodes[0]` is the root.
    /// * The parent of `nodes[i]` is `nodes[(i-1)/2]`.
    /// * The children of `nodes[i]` are `{nodes[2i + 1], nodes[2i + 2]}`.
    /// * Every stored node is one field element, including hashed leaves.
    nodes: Vec<F>,
    /// The leaves begin at `nodes[leaf_off]`.
    leaf_off: usize,
    /// Number of leaves stored in the Merkle tree.
    n: usize,
}

fn parent(i: usize) -> usize {
    assert!(i > 0, "The root node does not have a parent");
    (i - 1) / 2
}

fn left_child(i: usize) -> usize {
    (2 * i) + 1
}

fn right_child(i: usize) -> usize {
    (2 * i) + 2
}

fn sibling(i: usize) -> usize {
    assert!(i > 0, "The root node does not have a sibling");
    // Left children have odd indices; their right siblings follow immediately.
    // This assumes a complete binary heap.
    if i % 2 == 1 { i + 1 } else { i - 1 }
}

impl MerkleTree {
    /// Builds a tree from the ordered registry leaves.
    ///
    /// The leaf capacity is rounded up to the next power of two. Absent leaf
    /// children are represented by `Poseidon([0])`.
    ///
    /// # Panics
    ///
    /// Panics if the leaf list is empty.
    pub fn create(leaves: &[MTLeaf]) -> MerkleTree {
        let n = leaves.len();
        assert!(n > 0, "MerkleTree::create() called with no leaves");

        let num_nodes = n + n.next_power_of_two() - 1;
        let mut nodes = vec![F::ZERO; num_nodes];

        for i in 0..leaves.len() {
            nodes[num_nodes - n + i] = PoseidonHash::hash(&leaves[i].to_field());
        }

        let z = PoseidonHash::hash(&[F::ZERO]);
        for i in (0..num_nodes - n).rev() {
            let left = if left_child(i) < num_nodes {
                nodes[left_child(i)]
            } else {
                z
            };
            let right = if right_child(i) < num_nodes {
                nodes[right_child(i)]
            } else {
                z
            };
            nodes[i] = PoseidonHash::hash(&[left, right]);
        }

        Self {
            nodes,
            n,
            leaf_off: num_nodes - n,
        }
    }

    /// Returns the root of the tree.
    pub fn root(&self) -> F {
        self.nodes[0]
    }

    /// Returns the index of the leaf.
    fn idx_of_leaf(&self, i: usize) -> usize {
        self.leaf_off + i
    }

    /// Constructs a membership path for zero-based registry position `i`.
    ///
    /// # Panics
    ///
    /// Panics if `i` is outside the registered leaf list.
    pub fn get_path(&self, i: usize) -> MerklePath {
        assert!(
            i < self.n,
            "Proof index out of bounds: asked for {} out of {}",
            i,
            self.n
        );
        let mut idx = self.idx_of_leaf(i);
        let z = PoseidonHash::hash(&[F::ZERO]);
        let mut proof = Vec::new();

        while idx > 0 {
            let h = if sibling(idx) < self.nodes.len() {
                self.nodes[sibling(idx)]
            } else {
                z
            };
            let pos = {
                if (idx & 0b1) == 0 {
                    Position::Left
                } else {
                    Position::Right
                }
            };
            proof.push((pos, h));
            idx = parent(idx);
        }

        MerklePath::new(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schnorr_signature::SigningKey;
    use rand_core::OsRng;

    fn create_leaf(value: F) -> MTLeaf {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = VerificationKey::from(&sk);
        MTLeaf(vk, value)
    }

    #[test]
    fn test_merkle_tree_creation() {
        let leaves = vec![
            create_leaf(F::from(1u64)),
            create_leaf(F::from(2u64)),
            create_leaf(F::from(3u64)),
            create_leaf(F::from(4u64)),
        ];

        let tree = MerkleTree::create(&leaves);
        assert_eq!(tree.n, leaves.len(), "Number of leaves mismatch");
        assert!(
            tree.root() != F::ZERO,
            "Root should not be zero when tree is valid"
        );
    }

    #[test]
    fn test_merkle_path_generation() {
        let leaves = vec![
            create_leaf(F::from(1u64)),
            create_leaf(F::from(2u64)),
            create_leaf(F::from(3u64)),
            create_leaf(F::from(4u64)),
        ];

        let tree = MerkleTree::create(&leaves);

        for i in 0..leaves.len() {
            let path = tree.get_path(i);
            assert!(
                !path.siblings.is_empty(),
                "Path should not be empty for any leaf"
            );
        }
    }

    #[test]
    fn test_merkle_path_verification() {
        let leaves = vec![
            create_leaf(F::from(1u64)),
            create_leaf(F::from(2u64)),
            create_leaf(F::from(3u64)),
            create_leaf(F::from(4u64)),
            create_leaf(F::from(5u64)),
            create_leaf(F::from(6u64)),
        ];

        let tree = MerkleTree::create(&leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let path = tree.get_path(i);
            println!("{:?}", path.get_siblings().len());
            let computed_root = path.compute_root(*leaf);
            assert_eq!(
                tree.root(),
                computed_root,
                "Computed root does not match the actual root"
            );
        }
    }
}
