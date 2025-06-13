use crate::hasher::Hasher;

#[derive(Debug, Clone)]
enum NodeType {
    Leaf,
    Internal(Box<Node>, Box<Node>),
}

impl NodeType {
    pub fn left(&self) -> Option<&Box<Node>> {
        match self {
            NodeType::Leaf => None,
            NodeType::Internal(l, _) => Some(l),
        }
    }

    pub fn right(&self) -> Option<&Box<Node>> {
        match self {
            NodeType::Leaf => None,
            NodeType::Internal(_, r) => Some(r),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    hash: String,
    kind: NodeType,
}

impl Node {
    pub fn new_leaf<T: ToString>(hasher: &dyn Hasher, data: T) -> Self {
        let hash = hasher.hash(&data.to_string());
        Self {
            hash,
            kind: NodeType::Leaf,
        }
    }

    pub fn new_internal(hasher: &dyn Hasher, left: Node, right: Node) -> Self {
        let combined = format!("{}{}", left.hash, right.hash);
        let hash = hasher.hash(&combined);
        Self {
            hash,
            kind: NodeType::Internal(Box::new(left), Box::new(right)),
        }
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn kind(&self) -> &NodeType {
        &self.kind
    }
}
