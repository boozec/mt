use crate::{hasher::Hasher, merkle::node::Node};

#[derive(Debug)]
pub struct MerkleTree {
    leaves: Vec<Node>,
    height: usize,
    root: Node,
}

impl MerkleTree {
    pub fn new<T: ToString>(hasher: &dyn Hasher, data: Vec<T>) -> Self {
        assert!(
            !data.is_empty(),
            "Merkle Tree requires at least one element"
        );

        let mut leaves: Vec<Node> = data
            .into_iter()
            .map(|x| Node::new_leaf(hasher, x))
            .collect();
        if leaves.len() % 2 != 0 {
            leaves.push(leaves[leaves.len() - 1].clone());
        }

        Self::build(hasher, leaves)
    }

    fn build(hasher: &dyn Hasher, mut nodes: Vec<Node>) -> Self {
        let leaves = nodes.clone();
        let mut height = 0;

        while nodes.len() > 1 {
            let mut next_level = Vec::new();
            for pair in nodes.chunks(2) {
                let (left, right) = (pair[0].clone(), pair[1].clone());
                next_level.push(Node::new_internal(hasher, left, right));
            }
            nodes = next_level;
            height += 1;
        }

        let root = nodes.remove(0);

        MerkleTree {
            leaves,
            height: height + 1,
            root,
        }
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn root(&self) -> Node {
        self.root.clone()
    }
}
