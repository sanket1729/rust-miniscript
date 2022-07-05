//! Support for multi-signature keys
use core::fmt;
use core::str::FromStr;

use crate::expression::{FromTree, Tree};
use crate::prelude::*;
use crate::{Error, MiniscriptKey};

#[derive(Clone, PartialEq, PartialOrd, Ord, Eq, Hash)]
/// Enum for representing musig keys in miniscript
pub enum KeyExpr<Pk: MiniscriptKey> {
    /// Single-key (e.g pk(a), here 'a' is a single key)
    SingleKey(Pk),

    /// Collection of keys in used for musig-signature
    MuSig(Vec<KeyExpr<Pk>>),
}

impl<Pk: MiniscriptKey + FromStr> FromTree for KeyExpr<Pk> {
    fn from_tree(tree: &Tree) -> Result<KeyExpr<Pk>, Error> {
        if tree.name == "musig" {
            let mut key_expr_vec = vec![];
            for sub_tree in tree.args.iter() {
                let temp_res = KeyExpr::<Pk>::from_tree(sub_tree)?;
                key_expr_vec.push(temp_res);
            }
            Ok(KeyExpr::MuSig(key_expr_vec))
        } else {
            let single_key = Pk::from_str(tree.name).map_err(|_| Error::SingleKeyParseError)?;
            Ok(KeyExpr::SingleKey(single_key))
        }
    }
}

impl<Pk: MiniscriptKey + FromStr> FromStr for KeyExpr<Pk> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (key_tree, _) = Tree::from_slice(s).unwrap();
        FromTree::from_tree(&key_tree)
    }
}

#[derive(Debug, Clone)]
/// Iterator for keyexpr
pub struct KeyExprIter<'a, Pk: MiniscriptKey> {
    stack: Vec<&'a KeyExpr<Pk>>,
}

impl<'a, Pk> Iterator for KeyExprIter<'a, Pk>
where
    Pk: MiniscriptKey + 'a,
{
    type Item = &'a Pk;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.stack.is_empty() {
            let last = self.stack.pop().expect("Size checked above");
            match &*last {
                KeyExpr::MuSig(key_vec) => {
                    // push the elements in reverse order
                    for key in key_vec.iter().rev() {
                        self.stack.push(key)
                    }
                }
                KeyExpr::SingleKey(ref pk) => return Some(pk),
            }
        }
        None
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for KeyExpr<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeyExpr::SingleKey(ref pk) => write!(f, "{:?}", pk),
            KeyExpr::MuSig(ref my_vec) => {
                write!(f, "musig(")?;
                let len = my_vec.len();
                for (index, k) in my_vec.iter().enumerate() {
                    if index == len - 1 {
                        write!(f, "{:?}", k)?;
                    } else {
                        write!(f, "{:?}", k)?;
                    }
                }
                f.write_str(")")
            }
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Display for KeyExpr<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeyExpr::SingleKey(ref pk) => write!(f, "{}", pk),
            KeyExpr::MuSig(ref my_vec) => {
                write!(f, "musig(")?;
                let len = my_vec.len();
                for (index, k) in my_vec.iter().enumerate() {
                    if index == len - 1 {
                        write!(f, "{}", k)?;
                    } else {
                        write!(f, "{},", k)?;
                    }
                }
                f.write_str(")")
            }
        }
    }
}

impl<Pk: MiniscriptKey> KeyExpr<Pk> {
    /// Iterate over all keys
    pub fn iter(&self) -> KeyExprIter<Pk> {
        KeyExprIter { stack: vec![self] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_one(musig_key: &str) {
        let pk = KeyExpr::<String>::from_str(musig_key).unwrap();
        println!("{}", pk);
        dbg!(&pk);
        assert_eq!(musig_key, format!("{}", pk))
    }

    #[test]
    fn test_from_str_and_fmt() {
        test_one("musig(A,B,musig(C,musig(D,E)))");
        test_one("musig(A)");
        test_one("A");
        test_one("musig(,,)");
    }

    #[test]
    fn test_iterator() {
        let pk = KeyExpr::<String>::from_str("musig(A,B,musig(C,musig(D,E)))").unwrap();
        let mut my_iter = pk.iter();
        assert_eq!(my_iter.next(), Some(&String::from("A")));
        assert_eq!(my_iter.next(), Some(&String::from("B")));
        assert_eq!(my_iter.next(), Some(&String::from("C")));
        assert_eq!(my_iter.next(), Some(&String::from("D")));
        assert_eq!(my_iter.next(), Some(&String::from("E")));
        assert_eq!(my_iter.next(), None);
    }
}
