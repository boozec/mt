//! Contains node definitions for Merkle trees, including leaf and internal node structures.

/// Enum representing the type of the node child.
#[derive(Debug, Clone)]
pub enum NodeChildType {
    /// Left child
    Left,
    /// Right child
    Right,
}

/// Enum representing the type of a Merkle tree node.
#[derive(Clone)]
pub enum NodeStatus {
    /// A leaf node that contains no children.
    Leaf,
    /// An internal node that has two children.
    Internal(Box<Node>, Box<Node>),
}

impl NodeStatus {
    /// Returns a reference to the left child if the node is internal.
    pub fn left(&self) -> Option<&Node> {
        match self {
            NodeStatus::Leaf => None,
            NodeStatus::Internal(l, _) => Some(l),
        }
    }

    /// Returns a reference to the right child if the node is internal.
    pub fn right(&self) -> Option<&Node> {
        match self {
            NodeStatus::Leaf => None,
            NodeStatus::Internal(_, r) => Some(r),
        }
    }
}

/// Represents a node in a Merkle tree, either leaf or internal.
#[derive(Clone)]
pub struct Node {
    /// Hash value stored at the node.
    hash: String,
    /// Type of the node: leaf or internal.
    status: NodeStatus,
}

impl Node {
    /// Constructs a new leaf node from input data.
    ///
    /// # Arguments
    ///
    /// * `hasher` - A reference to a hashing strategy.
    pub fn new_leaf(hash: String) -> Self {
        Self {
            hash,
            status: NodeStatus::Leaf,
        }
    }

    /// Constructs a new internal node from two child nodes.
    ///
    /// # Arguments
    ///
    /// * `hash` - An hash value for the following node.
    /// * `left` - Left child node.
    /// * `right` - Right child node.
    ///
    /// # Behavior
    ///
    /// The internal node hash is computed as the hash of the concatenated children's hashes.
    pub fn new_internal(hash: String, left: Node, right: Node) -> Self {
        Self {
            hash,
            status: NodeStatus::Internal(Box::new(left), Box::new(right)),
        }
    }

    /// Returns a reference to the hash of the node.
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Returns a reference to the node's type (leaf or internal).
    pub fn status(&self) -> &NodeStatus {
        &self.status
    }
}
