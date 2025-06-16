//! Contains node definitions for Merkle trees, including leaf and internal node structures.

/// Enum representing the type of a Merkle tree node.
#[derive(Clone)]
pub enum NodeType {
    /// A leaf node that contains no children.
    Leaf,
    /// An internal node that has two children.
    Internal(Box<Node>, Box<Node>),
}

impl NodeType {
    /// Returns a reference to the left child if the node is internal.
    pub fn left(&self) -> Option<&Node> {
        match self {
            NodeType::Leaf => None,
            NodeType::Internal(l, _) => Some(l),
        }
    }

    /// Returns a reference to the right child if the node is internal.
    pub fn right(&self) -> Option<&Node> {
        match self {
            NodeType::Leaf => None,
            NodeType::Internal(_, r) => Some(r),
        }
    }
}

/// Represents a node in a Merkle tree, either leaf or internal.
#[derive(Clone)]
pub struct Node {
    /// Hash value stored at the node.
    hash: String,
    /// Type of the node: leaf or internal.
    kind: NodeType,
    /// Data in bytes.
    data: Vec<u8>,
}

impl Node {
    /// Constructs a new leaf node from input data.
    ///
    /// # Arguments
    ///
    /// * `hasher` - A reference to a hashing strategy.
    /// * `data` - The data to be hashed and stored as a leaf.
    pub fn new_leaf(data: &[u8], hash: String) -> Self {
        Self {
            hash,
            data: data.to_vec(),
            kind: NodeType::Leaf,
        }
    }

    /// Constructs a new internal node from two child nodes.
    ///
    /// # Arguments
    ///
    /// * `hasher` - A reference to a hashing strategy.
    /// * `left` - Left child node.
    /// * `right` - Right child node.
    ///
    /// # Behavior
    ///
    /// The internal node hash is computed as the hash of the concatenated children's hashes.
    pub fn new_internal(data: &[u8], hash: String, left: Node, right: Node) -> Self {
        Self {
            hash,
            data: data.to_vec(),
            kind: NodeType::Internal(Box::new(left), Box::new(right)),
        }
    }

    /// Returns a reference to the hash of the node.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Returns the data value in bytes format.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns a reference to the node's type (leaf or internal).
    pub fn kind(&self) -> &NodeType {
        &self.kind
    }
}
