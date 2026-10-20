//! Canonical compressed proofs for native USDOM sparse authenticated sets.

use std::{collections::BTreeMap, error::Error, fmt, sync::OnceLock};

use dom_core::blake2b_256_tagged;
use dom_core::Hash256;

const MAGIC: &[u8; 8] = b"UDSMPR01";
const PATH_TAG: &str = "DOM:usdom-sparse-path:v1";
const EMPTY_TAG: &str = "DOM:usdom-sparse-empty:v1";
const NODE_TAG: &str = "DOM:usdom-sparse-node:v1";
const DEPTH: usize = 256;
const MAX_KIND: u8 = 7;
const HEADER_BYTES: usize = 8 + 1 + 32 + 32 + 2;
const TREE_MAGIC: &[u8; 8] = b"UDSMTR01";
const TREE_HEADER_BYTES: usize = 8 + 1 + 8;

/// Maximum canonical encoding of one depth-256 sparse path.
pub const MAX_SPARSE_PROOF_BYTES: usize = HEADER_BYTES + DEPTH * 32;
/// Maximum optional compressed-tree cache snapshot accepted by the decoder.
/// The cache is rebuildable and does not limit consensus state size.
pub const MAX_SPARSE_TREE_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;

/// Failure while decoding or applying a native sparse-set path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparseProofError {
    /// Magic, size, bitmap, sibling count, or canonical omission is invalid.
    InvalidEncoding,
    /// Tree kind or key is zero.
    InvalidIdentity,
    /// Distinct keys address the same 256-bit path.
    PathCollision,
    /// The supplied old leaf and path do not open the expected root.
    RootMismatch,
}

impl fmt::Display for SparseProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid native sparse proof encoding",
            Self::InvalidIdentity => "invalid native sparse proof identity",
            Self::PathCollision => "native sparse proof path collision",
            Self::RootMismatch => "native sparse proof root mismatch",
        })
    }
}

impl Error for SparseProofError {}

/// One compressed depth-256 membership or nonmembership path.
///
/// Siblings are ordered from leaf level toward the root. `sibling_bitmap` has
/// one bit per level in the same order; zero bits select the deterministic
/// empty root for that level. Explicitly carrying an empty sibling is rejected
/// so every path has one encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMerkleProof {
    kind: u8,
    key: [u8; 32],
    sibling_bitmap: [u8; 32],
    siblings: Vec<Hash256>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SparseNode {
    Leaf {
        path: [u8; 32],
        leaf: Hash256,
    },
    Branch {
        depth: u16,
        path: [u8; 32],
        left: Box<SparseNode>,
        right: Box<SparseNode>,
        hash: Hash256,
    },
}

/// In-memory compressed sparse tree with bounded 256-hash insertions.
///
/// Only actual leaves and binary branch points are stored, so memory grows
/// linearly with the number of keys rather than with `keys * 256`. Unary paths
/// are reconstructed from deterministic empty roots when hashing or proving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseMerkleTree {
    kind: u8,
    root: Option<Box<SparseNode>>,
    leaf_count: u64,
}

impl SparseMerkleTree {
    /// Create an empty tree for one of the seven frozen native set domains.
    pub fn new(kind: u8) -> Result<Self, SparseProofError> {
        validate_kind(kind)?;
        Ok(Self {
            kind,
            root: None,
            leaf_count: 0,
        })
    }

    /// Build a tree from a unique keyed host snapshot.
    pub fn from_leaves(
        kind: u8,
        leaves: &BTreeMap<[u8; 32], Hash256>,
    ) -> Result<Self, SparseProofError> {
        let mut tree = Self::new(kind)?;
        for (key, leaf) in leaves {
            tree.insert(*key, *leaf)?;
        }
        Ok(tree)
    }

    /// Number of committed leaves.
    pub const fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Current canonical depth-256 root.
    pub fn root(&self) -> Hash256 {
        let empty = empty_roots(self.kind);
        self.root
            .as_deref()
            .map_or(empty[DEPTH], |node| lift_hash(self.kind, node, 0, empty))
    }

    /// Return the exact leaf committed at `key`, when present.
    pub fn leaf(&self, key: [u8; 32]) -> Result<Option<Hash256>, SparseProofError> {
        if key == [0; 32] {
            return Err(SparseProofError::InvalidIdentity);
        }
        let path = sparse_path(self.kind, key);
        Ok(self.root.as_deref().and_then(|root| find_leaf(root, &path)))
    }

    /// Insert one previously absent key in at most one 256-level rehash.
    pub fn insert(&mut self, key: [u8; 32], leaf: Hash256) -> Result<(), SparseProofError> {
        if key == [0; 32] || leaf == empty_roots(self.kind)[0] {
            return Err(SparseProofError::InvalidIdentity);
        }
        let path = sparse_path(self.kind, key);
        if self
            .root
            .as_deref()
            .is_some_and(|root| contains_path(root, &path))
        {
            return Err(SparseProofError::PathCollision);
        }
        let next_count = self
            .leaf_count
            .checked_add(1)
            .ok_or(SparseProofError::InvalidIdentity)?;
        let inserted = SparseNode::Leaf { path, leaf };
        self.root = Some(match self.root.take() {
            None => Box::new(inserted),
            Some(root) => insert_node(self.kind, root, inserted, empty_roots(self.kind))?,
        });
        self.leaf_count = next_count;
        Ok(())
    }

    /// Remove one exact existing key/leaf atomically for rollback.
    pub fn remove(
        &mut self,
        key: [u8; 32],
        expected_leaf: Hash256,
    ) -> Result<(), SparseProofError> {
        if key == [0; 32] || expected_leaf == empty_roots(self.kind)[0] {
            return Err(SparseProofError::InvalidIdentity);
        }
        let path = sparse_path(self.kind, key);
        if self.root.as_deref().and_then(|root| find_leaf(root, &path)) != Some(expected_leaf) {
            return Err(SparseProofError::RootMismatch);
        }
        let root = self.root.take().ok_or(SparseProofError::RootMismatch)?;
        self.root = remove_node(self.kind, *root, &path, empty_roots(self.kind));
        self.leaf_count -= 1;
        Ok(())
    }

    /// Produce the unique compressed membership or nonmembership path.
    pub fn prove(&self, key: [u8; 32]) -> Result<SparseMerkleProof, SparseProofError> {
        if key == [0; 32] {
            return Err(SparseProofError::InvalidIdentity);
        }
        let target = sparse_path(self.kind, key);
        let empty = empty_roots(self.kind);
        let mut by_level = [None; DEPTH];
        if let Some(root) = self.root.as_deref() {
            collect_tree_siblings(self.kind, root, &target, empty, &mut by_level)?;
        }
        let mut bitmap = [0u8; 32];
        let mut siblings = Vec::new();
        for (level, sibling) in by_level.into_iter().enumerate() {
            if let Some(sibling) = sibling {
                if sibling == empty[level] {
                    return Err(SparseProofError::InvalidEncoding);
                }
                set_bitmap_bit(&mut bitmap, level);
                siblings.push(sibling);
            }
        }
        SparseMerkleProof::new(self.kind, key, bitmap, siblings)
    }

    /// Encode an optional rebuildable cache snapshot in canonical path order.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SparseProofError> {
        let mut leaves = Vec::new();
        if let Some(root) = self.root.as_deref() {
            collect_tree_leaves(root, &mut leaves);
        }
        if leaves.len() as u64 != self.leaf_count {
            return Err(SparseProofError::InvalidEncoding);
        }
        let length = TREE_HEADER_BYTES
            .checked_add(
                leaves
                    .len()
                    .checked_mul(64)
                    .ok_or(SparseProofError::InvalidEncoding)?,
            )
            .ok_or(SparseProofError::InvalidEncoding)?;
        if length > MAX_SPARSE_TREE_SNAPSHOT_BYTES {
            return Err(SparseProofError::InvalidEncoding);
        }
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(TREE_MAGIC);
        bytes.push(self.kind);
        bytes.extend_from_slice(&self.leaf_count.to_be_bytes());
        for (path, leaf) in leaves {
            bytes.extend_from_slice(&path);
            bytes.extend_from_slice(leaf.as_bytes());
        }
        Ok(bytes)
    }

    /// Decode and re-encode one exact optional cache snapshot.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SparseProofError> {
        if bytes.len() < TREE_HEADER_BYTES
            || bytes.len() > MAX_SPARSE_TREE_SNAPSHOT_BYTES
            || &bytes[..8] != TREE_MAGIC
        {
            return Err(SparseProofError::InvalidEncoding);
        }
        let kind = bytes[8];
        validate_kind(kind)?;
        let count = u64::from_be_bytes(take_array(bytes, 9)?);
        let count_usize: usize = count
            .try_into()
            .map_err(|_| SparseProofError::InvalidEncoding)?;
        let expected = TREE_HEADER_BYTES
            .checked_add(
                count_usize
                    .checked_mul(64)
                    .ok_or(SparseProofError::InvalidEncoding)?,
            )
            .ok_or(SparseProofError::InvalidEncoding)?;
        if expected != bytes.len() {
            return Err(SparseProofError::InvalidEncoding);
        }
        let mut tree = Self::new(kind)?;
        let mut previous = None;
        let mut cursor = TREE_HEADER_BYTES;
        for _ in 0..count_usize {
            let path = take_array(bytes, cursor)?;
            let leaf = Hash256::from_bytes(take_array(bytes, cursor + 32)?);
            cursor += 64;
            if previous.is_some_and(|value| value >= path) {
                return Err(SparseProofError::InvalidEncoding);
            }
            previous = Some(path);
            tree.insert_path(path, leaf)?;
        }
        if tree.to_bytes()?.as_slice() != bytes {
            return Err(SparseProofError::InvalidEncoding);
        }
        Ok(tree)
    }

    fn insert_path(&mut self, path: [u8; 32], leaf: Hash256) -> Result<(), SparseProofError> {
        if leaf == empty_roots(self.kind)[0]
            || self
                .root
                .as_deref()
                .is_some_and(|root| contains_path(root, &path))
        {
            return Err(SparseProofError::InvalidEncoding);
        }
        let next_count = self
            .leaf_count
            .checked_add(1)
            .ok_or(SparseProofError::InvalidEncoding)?;
        let inserted = SparseNode::Leaf { path, leaf };
        self.root = Some(match self.root.take() {
            None => Box::new(inserted),
            Some(root) => insert_node(self.kind, root, inserted, empty_roots(self.kind))?,
        });
        self.leaf_count = next_count;
        Ok(())
    }
}

impl SparseMerkleProof {
    /// Construct and canonically validate a compressed path.
    pub fn new(
        kind: u8,
        key: [u8; 32],
        sibling_bitmap: [u8; 32],
        siblings: Vec<Hash256>,
    ) -> Result<Self, SparseProofError> {
        let proof = Self {
            kind,
            key,
            sibling_bitmap,
            siblings,
        };
        proof.validate()?;
        Ok(proof)
    }

    /// Domain byte selecting the native set.
    pub const fn kind(&self) -> u8 {
        self.kind
    }

    /// Unhashed native set key.
    pub const fn key(&self) -> [u8; 32] {
        self.key
    }

    /// Compute the root opened by `leaf`; `None` proves canonical emptiness.
    pub fn root(&self, leaf: Option<Hash256>) -> Result<Hash256, SparseProofError> {
        self.validate()?;
        let path = sparse_path(self.kind, self.key);
        let empty = empty_roots(self.kind);
        let mut supplied = self.siblings.iter();
        let mut current = leaf.unwrap_or(empty[0]);
        if leaf.is_some_and(|value| value == empty[0]) {
            return Err(SparseProofError::InvalidEncoding);
        }
        for (level, empty_at_level) in empty.iter().copied().enumerate().take(DEPTH) {
            let sibling = if bitmap_bit(&self.sibling_bitmap, level) {
                *supplied.next().ok_or(SparseProofError::InvalidEncoding)?
            } else {
                empty_at_level
            };
            let root_depth = DEPTH - 1 - level;
            current = if path_bit(&path, root_depth) {
                node_hash(self.kind, level as u16, sibling, current)
            } else {
                node_hash(self.kind, level as u16, current, sibling)
            };
        }
        if supplied.next().is_some() {
            return Err(SparseProofError::InvalidEncoding);
        }
        Ok(current)
    }

    /// Verify `old_leaf` against `expected_root` and return the root after
    /// replacing it with `new_leaf`. `None` is the canonical empty leaf.
    pub fn update_root(
        &self,
        expected_root: Hash256,
        old_leaf: Option<Hash256>,
        new_leaf: Option<Hash256>,
    ) -> Result<Hash256, SparseProofError> {
        if self.root(old_leaf)? != expected_root {
            return Err(SparseProofError::RootMismatch);
        }
        self.root(new_leaf)
    }

    /// Encode the unique bounded `UDSMPR01` representation.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SparseProofError> {
        self.validate()?;
        let count: u16 = self
            .siblings
            .len()
            .try_into()
            .map_err(|_| SparseProofError::InvalidEncoding)?;
        let mut bytes = Vec::with_capacity(HEADER_BYTES + self.siblings.len() * 32);
        bytes.extend_from_slice(MAGIC);
        bytes.push(self.kind);
        bytes.extend_from_slice(&self.key);
        bytes.extend_from_slice(&self.sibling_bitmap);
        bytes.extend_from_slice(&count.to_be_bytes());
        for sibling in &self.siblings {
            bytes.extend_from_slice(sibling.as_bytes());
        }
        Ok(bytes)
    }

    /// Decode, validate, and re-encode one exact `UDSMPR01` path.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SparseProofError> {
        if bytes.len() < HEADER_BYTES
            || bytes.len() > MAX_SPARSE_PROOF_BYTES
            || &bytes[..8] != MAGIC
        {
            return Err(SparseProofError::InvalidEncoding);
        }
        let kind = bytes[8];
        let key = take_array(bytes, 9)?;
        let sibling_bitmap = take_array(bytes, 41)?;
        let count = usize::from(u16::from_be_bytes(take_array(bytes, 73)?));
        let expected = HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(32)
                    .ok_or(SparseProofError::InvalidEncoding)?,
            )
            .ok_or(SparseProofError::InvalidEncoding)?;
        if expected != bytes.len() || count > DEPTH {
            return Err(SparseProofError::InvalidEncoding);
        }
        let mut siblings = Vec::with_capacity(count);
        let mut cursor = HEADER_BYTES;
        for _ in 0..count {
            siblings.push(Hash256::from_bytes(take_array(bytes, cursor)?));
            cursor += 32;
        }
        let proof = Self::new(kind, key, sibling_bitmap, siblings)?;
        if proof.to_bytes()?.as_slice() != bytes {
            return Err(SparseProofError::InvalidEncoding);
        }
        Ok(proof)
    }

    fn validate(&self) -> Result<(), SparseProofError> {
        if self.kind == 0
            || self.kind > MAX_KIND
            || self.key == [0; 32]
            || self.siblings.len() > DEPTH
        {
            return Err(SparseProofError::InvalidIdentity);
        }
        let bit_count: usize = self
            .sibling_bitmap
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum();
        if bit_count != self.siblings.len() {
            return Err(SparseProofError::InvalidEncoding);
        }
        let empty = empty_roots(self.kind);
        let mut supplied = self.siblings.iter();
        for (level, empty_at_level) in empty.iter().copied().enumerate().take(DEPTH) {
            if bitmap_bit(&self.sibling_bitmap, level)
                && *supplied.next().ok_or(SparseProofError::InvalidEncoding)? == empty_at_level
            {
                return Err(SparseProofError::InvalidEncoding);
            }
        }
        if supplied.next().is_some() {
            return Err(SparseProofError::InvalidEncoding);
        }
        Ok(())
    }

    /// Construct the unique compressed path from a complete host snapshot.
    /// This helper is for witness generation; verification needs only the
    /// expected root, leaf value, and encoded proof.
    pub fn from_leaves(
        kind: u8,
        key: [u8; 32],
        leaves: &BTreeMap<[u8; 32], Hash256>,
    ) -> Result<Self, SparseProofError> {
        if kind == 0 || kind > MAX_KIND || key == [0; 32] {
            return Err(SparseProofError::InvalidIdentity);
        }
        let paths = canonical_paths(kind, leaves)?;
        let path = sparse_path(kind, key);
        let empty = empty_roots(kind);
        let mut bitmap = [0u8; 32];
        let mut siblings = Vec::new();
        collect_siblings(kind, &paths, &path, 0, empty, &mut bitmap, &mut siblings);
        Self::new(kind, key, bitmap, siblings)
    }
}

fn sparse_path(kind: u8, key: [u8; 32]) -> [u8; 32] {
    let mut bytes = [0u8; 33];
    bytes[0] = kind;
    bytes[1..].copy_from_slice(&key);
    *blake2b_256_tagged(PATH_TAG, &bytes).as_bytes()
}

fn empty_roots(kind: u8) -> &'static [Hash256; DEPTH + 1] {
    static ROOTS_1: OnceLock<[Hash256; DEPTH + 1]> = OnceLock::new();
    static ROOTS_2: OnceLock<[Hash256; DEPTH + 1]> = OnceLock::new();
    static ROOTS_3: OnceLock<[Hash256; DEPTH + 1]> = OnceLock::new();
    static ROOTS_4: OnceLock<[Hash256; DEPTH + 1]> = OnceLock::new();
    static ROOTS_5: OnceLock<[Hash256; DEPTH + 1]> = OnceLock::new();
    static ROOTS_6: OnceLock<[Hash256; DEPTH + 1]> = OnceLock::new();
    static ROOTS_7: OnceLock<[Hash256; DEPTH + 1]> = OnceLock::new();
    static INVALID_ROOTS: OnceLock<[Hash256; DEPTH + 1]> = OnceLock::new();
    let roots = match kind {
        1 => &ROOTS_1,
        2 => &ROOTS_2,
        3 => &ROOTS_3,
        4 => &ROOTS_4,
        5 => &ROOTS_5,
        6 => &ROOTS_6,
        7 => &ROOTS_7,
        // Invalid kinds cannot enter a tree or proof through the public API.
        // Keep this private invariant total so corrupted in-memory state cannot
        // abort the process before the caller receives its normal validation
        // error.
        _ => &INVALID_ROOTS,
    };
    roots.get_or_init(|| compute_empty_roots(kind))
}

fn compute_empty_roots(kind: u8) -> [Hash256; DEPTH + 1] {
    let mut roots = [Hash256::ZERO; DEPTH + 1];
    roots[0] = blake2b_256_tagged(EMPTY_TAG, &[kind]);
    for level in 0..DEPTH {
        roots[level + 1] = node_hash(kind, level as u16, roots[level], roots[level]);
    }
    roots
}

fn node_hash(kind: u8, level: u16, left: Hash256, right: Hash256) -> Hash256 {
    let mut bytes = [0u8; 67];
    bytes[0] = kind;
    bytes[1..3].copy_from_slice(&level.to_be_bytes());
    bytes[3..35].copy_from_slice(left.as_bytes());
    bytes[35..].copy_from_slice(right.as_bytes());
    blake2b_256_tagged(NODE_TAG, &bytes)
}

fn validate_kind(kind: u8) -> Result<(), SparseProofError> {
    if kind == 0 || kind > MAX_KIND {
        Err(SparseProofError::InvalidIdentity)
    } else {
        Ok(())
    }
}

impl SparseNode {
    fn path(&self) -> &[u8; 32] {
        match self {
            Self::Leaf { path, .. } | Self::Branch { path, .. } => path,
        }
    }

    fn depth(&self) -> usize {
        match self {
            Self::Leaf { .. } => DEPTH,
            Self::Branch { depth, .. } => usize::from(*depth),
        }
    }

    fn hash(&self) -> Hash256 {
        match self {
            Self::Leaf { leaf, .. } => *leaf,
            Self::Branch { hash, .. } => *hash,
        }
    }
}

fn lift_hash(
    kind: u8,
    node: &SparseNode,
    target_depth: usize,
    empty: &[Hash256; DEPTH + 1],
) -> Hash256 {
    let mut current = node.hash();
    let mut depth = node.depth();
    while depth > target_depth {
        depth -= 1;
        let level = DEPTH - 1 - depth;
        current = if path_bit(node.path(), depth) {
            node_hash(kind, level as u16, empty[level], current)
        } else {
            node_hash(kind, level as u16, current, empty[level])
        };
    }
    current
}

fn branch_node(
    kind: u8,
    depth: usize,
    left: Box<SparseNode>,
    right: Box<SparseNode>,
    empty: &[Hash256; DEPTH + 1],
) -> Box<SparseNode> {
    debug_assert!(depth < DEPTH);
    debug_assert!(!path_bit(left.path(), depth));
    debug_assert!(path_bit(right.path(), depth));
    debug_assert!(prefix_equal(left.path(), right.path(), depth));
    let left_hash = lift_hash(kind, &left, depth + 1, empty);
    let right_hash = lift_hash(kind, &right, depth + 1, empty);
    let hash = node_hash(kind, (DEPTH - 1 - depth) as u16, left_hash, right_hash);
    Box::new(SparseNode::Branch {
        depth: depth as u16,
        path: *left.path(),
        left,
        right,
        hash,
    })
}

fn insert_node(
    kind: u8,
    node: Box<SparseNode>,
    inserted: SparseNode,
    empty: &[Hash256; DEPTH + 1],
) -> Result<Box<SparseNode>, SparseProofError> {
    let common = common_prefix(node.path(), inserted.path());
    debug_assert!(common < DEPTH);
    if common < node.depth() {
        return Ok(if path_bit(inserted.path(), common) {
            branch_node(kind, common, node, Box::new(inserted), empty)
        } else {
            branch_node(kind, common, Box::new(inserted), node, empty)
        });
    }
    let SparseNode::Branch {
        depth, left, right, ..
    } = *node
    else {
        return Err(SparseProofError::PathCollision);
    };
    let depth = usize::from(depth);
    if path_bit(inserted.path(), depth) {
        Ok(branch_node(
            kind,
            depth,
            left,
            insert_node(kind, right, inserted, empty)?,
            empty,
        ))
    } else {
        Ok(branch_node(
            kind,
            depth,
            insert_node(kind, left, inserted, empty)?,
            right,
            empty,
        ))
    }
}

fn contains_path(node: &SparseNode, target: &[u8; 32]) -> bool {
    if common_prefix(node.path(), target) < node.depth() {
        return false;
    }
    match node {
        SparseNode::Leaf { path, .. } => path == target,
        SparseNode::Branch {
            depth, left, right, ..
        } => {
            if path_bit(target, usize::from(*depth)) {
                contains_path(right, target)
            } else {
                contains_path(left, target)
            }
        }
    }
}

fn find_leaf(node: &SparseNode, target: &[u8; 32]) -> Option<Hash256> {
    if common_prefix(node.path(), target) < node.depth() {
        return None;
    }
    match node {
        SparseNode::Leaf { path, leaf } => (path == target).then_some(*leaf),
        SparseNode::Branch {
            depth, left, right, ..
        } => {
            if path_bit(target, usize::from(*depth)) {
                find_leaf(right, target)
            } else {
                find_leaf(left, target)
            }
        }
    }
}

fn remove_node(
    kind: u8,
    node: SparseNode,
    target: &[u8; 32],
    empty: &[Hash256; DEPTH + 1],
) -> Option<Box<SparseNode>> {
    match node {
        SparseNode::Leaf { path, .. } => {
            debug_assert_eq!(&path, target);
            None
        }
        SparseNode::Branch {
            depth, left, right, ..
        } => {
            let depth = usize::from(depth);
            if path_bit(target, depth) {
                match remove_node(kind, *right, target, empty) {
                    Some(next) => Some(branch_node(kind, depth, left, next, empty)),
                    None => Some(left),
                }
            } else {
                match remove_node(kind, *left, target, empty) {
                    Some(next) => Some(branch_node(kind, depth, next, right, empty)),
                    None => Some(right),
                }
            }
        }
    }
}

fn collect_tree_leaves(node: &SparseNode, leaves: &mut Vec<([u8; 32], Hash256)>) {
    match node {
        SparseNode::Leaf { path, leaf } => leaves.push((*path, *leaf)),
        SparseNode::Branch { left, right, .. } => {
            collect_tree_leaves(left, leaves);
            collect_tree_leaves(right, leaves);
        }
    }
}

fn collect_tree_siblings(
    kind: u8,
    node: &SparseNode,
    target: &[u8; 32],
    empty: &[Hash256; DEPTH + 1],
    by_level: &mut [Option<Hash256>; DEPTH],
) -> Result<(), SparseProofError> {
    let common = common_prefix(node.path(), target);
    if common < node.depth() {
        let level = DEPTH - 1 - common;
        by_level[level] = Some(lift_hash(kind, node, common + 1, empty));
        return Ok(());
    }
    match node {
        SparseNode::Leaf { .. } => Ok(()),
        SparseNode::Branch {
            depth, left, right, ..
        } => {
            let depth = usize::from(*depth);
            let level = DEPTH - 1 - depth;
            if path_bit(target, depth) {
                by_level[level] = Some(lift_hash(kind, left, depth + 1, empty));
                collect_tree_siblings(kind, right, target, empty, by_level)
            } else {
                by_level[level] = Some(lift_hash(kind, right, depth + 1, empty));
                collect_tree_siblings(kind, left, target, empty, by_level)
            }
        }
    }
}

fn common_prefix(left: &[u8; 32], right: &[u8; 32]) -> usize {
    for (index, (left, right)) in left.iter().zip(right).enumerate() {
        let difference = left ^ right;
        if difference != 0 {
            return index * 8 + difference.leading_zeros() as usize;
        }
    }
    DEPTH
}

fn prefix_equal(left: &[u8; 32], right: &[u8; 32], bits: usize) -> bool {
    common_prefix(left, right) >= bits
}

/// Compute the canonical sparse root of a complete keyed host snapshot.
pub fn sparse_root(
    kind: u8,
    leaves: &BTreeMap<[u8; 32], Hash256>,
) -> Result<Hash256, SparseProofError> {
    let paths = canonical_paths(kind, leaves)?;
    let empty = empty_roots(kind);
    Ok(subtree_root(kind, &paths, 0, empty))
}

fn subtree_root(
    kind: u8,
    leaves: &[([u8; 32], Hash256)],
    depth: usize,
    empty: &[Hash256; DEPTH + 1],
) -> Hash256 {
    let remaining = DEPTH - depth;
    if leaves.is_empty() {
        return empty[remaining];
    }
    if depth == DEPTH {
        return leaves[0].1;
    }
    let split = leaves.partition_point(|(path, _)| !path_bit(path, depth));
    let left = subtree_root(kind, &leaves[..split], depth + 1, empty);
    let right = subtree_root(kind, &leaves[split..], depth + 1, empty);
    node_hash(kind, (remaining - 1) as u16, left, right)
}

fn canonical_paths(
    kind: u8,
    leaves: &BTreeMap<[u8; 32], Hash256>,
) -> Result<Vec<([u8; 32], Hash256)>, SparseProofError> {
    if kind == 0 || kind > MAX_KIND {
        return Err(SparseProofError::InvalidIdentity);
    }
    let empty_leaf = empty_roots(kind)[0];
    let mut paths = Vec::with_capacity(leaves.len());
    for (key, leaf) in leaves {
        if *key == [0; 32] || *leaf == empty_leaf {
            return Err(SparseProofError::InvalidIdentity);
        }
        paths.push((sparse_path(kind, *key), *leaf));
    }
    paths.sort_unstable_by_key(|(path, _)| *path);
    if paths.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(SparseProofError::PathCollision);
    }
    Ok(paths)
}

#[allow(clippy::too_many_arguments)]
fn collect_siblings(
    kind: u8,
    leaves: &[([u8; 32], Hash256)],
    target: &[u8; 32],
    depth: usize,
    empty: &[Hash256; DEPTH + 1],
    bitmap: &mut [u8; 32],
    siblings: &mut Vec<Hash256>,
) {
    if depth == DEPTH {
        return;
    }
    let split = leaves.partition_point(|(path, _)| !path_bit(path, depth));
    let (selected, sibling) = if path_bit(target, depth) {
        (&leaves[split..], &leaves[..split])
    } else {
        (&leaves[..split], &leaves[split..])
    };
    let sibling_root = subtree_root(kind, sibling, depth + 1, empty);
    let level = DEPTH - 1 - depth;
    collect_siblings(kind, selected, target, depth + 1, empty, bitmap, siblings);
    if sibling_root != empty[level] {
        set_bitmap_bit(bitmap, level);
        siblings.push(sibling_root);
    }
}

fn path_bit(path: &[u8; 32], depth: usize) -> bool {
    path[depth / 8] & (0x80 >> (depth % 8)) != 0
}

fn bitmap_bit(bitmap: &[u8; 32], level: usize) -> bool {
    bitmap[level / 8] & (1 << (level % 8)) != 0
}

fn set_bitmap_bit(bitmap: &mut [u8; 32], level: usize) {
    bitmap[level / 8] |= 1 << (level % 8);
}

fn take_array<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], SparseProofError> {
    bytes
        .get(start..start + N)
        .ok_or(SparseProofError::InvalidEncoding)?
        .try_into()
        .map_err(|_| SparseProofError::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn leaf(value: u8) -> Hash256 {
        Hash256::from_bytes([value; 32])
    }

    #[test]
    fn sparse_decoders_reject_hostile_bounded_bytes_without_panicking() {
        for length in 0..=4_096 {
            for seed in [0u8, 0x5a, 0xff] {
                let mut proof = (0..length)
                    .map(|index| seed.wrapping_add((index as u8).wrapping_mul(73)))
                    .collect::<Vec<_>>();
                let prefix = MAGIC.len().min(proof.len());
                proof[..prefix].copy_from_slice(&MAGIC[..prefix]);
                let _ = SparseMerkleProof::from_bytes(&proof);

                let mut snapshot = proof;
                let prefix = TREE_MAGIC.len().min(snapshot.len());
                snapshot[..prefix].copy_from_slice(&TREE_MAGIC[..prefix]);
                let _ = SparseMerkleTree::from_bytes(&snapshot);
            }
        }
    }

    #[test]
    fn compressed_membership_nonmembership_and_updates_match_full_tree() {
        let kind = 4;
        let leaves = BTreeMap::from([(key(1), leaf(11)), (key(2), leaf(12)), (key(3), leaf(13))]);
        let root = sparse_root(kind, &leaves).expect("root");
        let membership = SparseMerkleProof::from_leaves(kind, key(2), &leaves).expect("proof");
        assert_eq!(membership.root(Some(leaf(12))).expect("open"), root);

        let absent = SparseMerkleProof::from_leaves(kind, key(9), &leaves).expect("absent proof");
        assert_eq!(absent.root(None).expect("empty open"), root);
        let inserted_root = absent
            .update_root(root, None, Some(leaf(19)))
            .expect("insert root");
        let mut inserted = leaves.clone();
        inserted.insert(key(9), leaf(19));
        assert_eq!(
            inserted_root,
            sparse_root(kind, &inserted).expect("full insert")
        );

        let deleted_root = membership
            .update_root(root, Some(leaf(12)), None)
            .expect("delete root");
        let mut deleted = leaves.clone();
        deleted.remove(&key(2));
        assert_eq!(
            deleted_root,
            sparse_root(kind, &deleted).expect("full delete")
        );
    }

    #[test]
    fn invalid_kind_cannot_initialize_or_alias_an_authenticated_tree() {
        let leaves = BTreeMap::from([(key(1), leaf(11))]);
        assert_eq!(
            sparse_root(0, &leaves),
            Err(SparseProofError::InvalidIdentity)
        );
        assert_eq!(
            sparse_root(8, &leaves),
            Err(SparseProofError::InvalidIdentity)
        );
        let root = sparse_root(1, &leaves).expect("kind one root");
        assert_eq!(
            SparseMerkleProof::from_leaves(1, key(1), &leaves)
                .expect("kind one proof")
                .root(Some(leaf(11)))
                .expect("open"),
            root
        );
    }

    #[test]
    fn compressed_tree_updates_and_proofs_match_full_reference_roots() {
        let mut leaves = BTreeMap::new();
        let mut tree = SparseMerkleTree::new(5).expect("tree");
        assert_eq!(tree.root(), sparse_root(5, &leaves).expect("empty root"));
        for value in 1u8..=64 {
            let key = key(value);
            let leaf = leaf(value.wrapping_add(80));
            let absence = tree.prove(key).expect("absence");
            assert_eq!(absence.root(None).expect("open absence"), tree.root());
            tree.insert(key, leaf).expect("insert");
            leaves.insert(key, leaf);
            assert_eq!(tree.leaf_count(), leaves.len() as u64);
            assert_eq!(tree.root(), sparse_root(5, &leaves).expect("reference"));
            let membership = tree.prove(key).expect("membership");
            assert_eq!(
                membership.root(Some(leaf)).expect("open membership"),
                tree.root()
            );
        }
        let absent = key(200);
        assert_eq!(
            tree.prove(absent)
                .expect("nonmembership")
                .root(None)
                .expect("open"),
            tree.root()
        );
        let before_duplicate = tree.root();
        assert_eq!(
            tree.insert(key(1), leaf(9)),
            Err(SparseProofError::PathCollision)
        );
        assert_eq!(tree.leaf_count(), 64);
        assert_eq!(tree.root(), before_duplicate);

        let snapshot = tree.to_bytes().expect("snapshot");
        assert!(snapshot.len() <= MAX_SPARSE_TREE_SNAPSHOT_BYTES);
        assert_eq!(
            SparseMerkleTree::from_bytes(&snapshot).expect("restore"),
            tree
        );
        let mut trailing = snapshot.clone();
        trailing.push(0);
        assert_eq!(
            SparseMerkleTree::from_bytes(&trailing),
            Err(SparseProofError::InvalidEncoding)
        );

        for value in (1u8..=64).rev() {
            let key = key(value);
            let expected_leaf = leaf(value.wrapping_add(80));
            let before_failed_remove = tree.root();
            assert_eq!(
                tree.remove(key, leaf(1)),
                Err(SparseProofError::RootMismatch)
            );
            assert_eq!(tree.root(), before_failed_remove);
            tree.remove(key, expected_leaf).expect("remove");
            leaves.remove(&key);
            assert_eq!(tree.leaf_count(), leaves.len() as u64);
            assert_eq!(tree.root(), sparse_root(5, &leaves).expect("reference"));
            assert_eq!(
                tree.prove(key)
                    .expect("absence after remove")
                    .root(None)
                    .expect("open"),
                tree.root()
            );
        }
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn encoding_round_trips_and_rejects_malleability() {
        let leaves = BTreeMap::from([(key(1), leaf(11)), (key(2), leaf(12))]);
        let proof = SparseMerkleProof::from_leaves(2, key(1), &leaves).expect("proof");
        let bytes = proof.to_bytes().expect("encode");
        assert!(bytes.len() <= MAX_SPARSE_PROOF_BYTES);
        assert_eq!(
            SparseMerkleProof::from_bytes(&bytes).expect("decode"),
            proof
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            SparseMerkleProof::from_bytes(&trailing),
            Err(SparseProofError::InvalidEncoding)
        );
        let mut wrong_count = bytes.clone();
        wrong_count[73..75].copy_from_slice(&256u16.to_be_bytes());
        assert_eq!(
            SparseMerkleProof::from_bytes(&wrong_count),
            Err(SparseProofError::InvalidEncoding)
        );
        assert_eq!(
            proof.update_root(Hash256::ZERO, Some(leaf(11)), Some(leaf(21))),
            Err(SparseProofError::RootMismatch)
        );
    }

    #[test]
    fn proof_vector_is_frozen() {
        let leaves = BTreeMap::from([(key(1), leaf(11)), (key(2), leaf(12)), (key(3), leaf(13))]);
        let proof = SparseMerkleProof::from_leaves(4, key(2), &leaves).expect("proof");
        assert_eq!(
            hex::encode(proof.to_bytes().expect("bytes")),
            "5544534d50523031040202020202020202020202020202020202020202020202020202020202020202000000000000000000000000000000000000000000000000000000000000001800025c15c87a990d5dca57de6faddcaf6c64deb4280f6b6d53208f4d4507c7ff137316349525d6220c64e269af810bf3ce5beb2bd28e10b499875ed5e6e30d957811"
        );
    }
}
