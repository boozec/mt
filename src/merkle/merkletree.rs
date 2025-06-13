use crate::{hasher::Hasher, merkle::node::Node};

#[derive(Debug)]
pub struct MerkleTree {
    leafs: Vec<Node>,
    height: usize,
    root: Node,
}

impl MerkleTree {
    pub fn new<T: ToString>(hasher: &dyn Hasher, data: Vec<T>) -> Self {
        assert!(
            !data.is_empty(),
            "Merkle Tree requires at least one element"
        );

        let mut leafs: Vec<Node> = data
            .into_iter()
            .map(|x| Node::new_leaf(hasher, x))
            .collect();
        if leafs.len() % 2 != 0 {
            leafs.push(leafs[leafs.len() - 1].clone());
        }

        Self::build(hasher, leafs)
    }

    fn build(hasher: &dyn Hasher, mut nodes: Vec<Node>) -> Self {
        let leafs = nodes.clone();
        let mut height = 0;

        while nodes.len() > 1 {
            let mut next_level = Vec::new();
            for pair in nodes.chunks(2) {
                let left = pair[0].clone();
                let right = if pair.len() == 2 {
                    pair[1].clone()
                } else {
                    left.clone()
                };
                next_level.push(Node::new_internal(hasher, left, right));
            }
            nodes = next_level;
            height += 1;
        }

        let root = nodes.remove(0);

        MerkleTree {
            leafs,
            height: height + 1,
            root,
        }
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn len(&self) -> usize {
        self.leafs.len()
    }

    pub fn root(&self) -> Node {
        self.root.clone()
    }
}
