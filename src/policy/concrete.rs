// Miniscript
// Written in 2019 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Concrete Policies
//!

use bitcoin_hashes::{hash160, ripemd160, sha256, sha256d};
use bitcoin_hashes::hex::FromHex;
use std::{fmt, str};
use std::str::FromStr;

#[cfg(feature = "compiler")] use policy::compiler;
#[cfg(feature = "compiler")] use Miniscript;
use expression::{self, FromTree};
use ::{Error, MiniscriptKey};
use errstr;

/// Concrete policy which corresponds directly to a Miniscript structure,
/// and whose disjunctions are annotated with satisfaction probabilities
/// to assist the compiler
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Policy<Pk: MiniscriptKey> {
    /// A public key which must sign to satisfy the descriptor
    Key(Pk),
    /// Public keyhash to satisfy, both a public key and a signature
    /// is required
    KeyHash(Pk::Hash),
    /// A relative locktime restriction
    After(u32),
    /// An absolute locktime restriction
    Older(u32),
    /// A SHA256 whose preimage must be provided to satisfy the descriptor
    Sha256(sha256::Hash),
    /// A SHA256d whose preimage must be provided to satisfy the descriptor
    Hash256(sha256d::Hash),
    /// A RIPEMD160 whose preimage must be provided to satisfy the descriptor
    Ripemd160(ripemd160::Hash),
    /// A HASH160 whose preimage must be provided to satisfy the descriptor
    Hash160(hash160::Hash),
    /// A list of sub-policies, all of which must be satisfied
    And(Vec<Policy<Pk>>),
    /// A list of sub-policies, one of which must be satisfied, along with
    /// relative probabilities for each one
    Or(Vec<(usize, Policy<Pk>)>),
    /// A set of descriptors, satisfactions must be provided for `k` of them
    Threshold(usize, Vec<Policy<Pk>>),
}

impl<Pk: MiniscriptKey> Policy<Pk>
{
    /// Compile the descriptor into an optimized `Miniscript` representation
    #[cfg(feature="compiler")]
    pub fn compile(&self) -> Miniscript<Pk> {
        Miniscript::from(compiler::best_compilation(self))
    }
}

impl<Pk: MiniscriptKey> Policy<Pk> {
    /// Convert a policy using one kind of public key to another
    /// type of public key
    pub fn translate_pk<Fpk, Fpkh, Q, E>(
        &self,
        mut translatefpk: Fpk,
        mut translatefpkh: Fpkh,
    ) -> Result<Policy<Q>, E>
        where Fpk: FnMut(&Pk) -> Result<Q, E>,
              Fpkh: FnMut(&Pk::Hash) -> Result<Q::Hash, E>,
              Q: MiniscriptKey
    {
        match *self {
            Policy::Key(ref pk) => translatefpk(pk).map(Policy::Key),
            Policy::KeyHash(ref pkh) => translatefpkh(pkh).map(Policy::KeyHash),
            Policy::Sha256(ref h) => Ok(Policy::Sha256(h.clone())),
            Policy::Hash256(ref h) => Ok(Policy::Hash256(h.clone())),
            Policy::Ripemd160(ref h) => Ok(Policy::Ripemd160(h.clone())),
            Policy::Hash160(ref h) => Ok(Policy::Hash160(h.clone())),
            Policy::After(n) => Ok(Policy::After(n)),
            Policy::Older(n) => Ok(Policy::Older(n)),
            Policy::Threshold(k, ref subs) => {
                let new_subs: Result<Vec<Policy<Q>>, _> = subs.iter().map(
                    |sub| sub.translate_pk(&mut translatefpk, &mut translatefpkh)
                ).collect();
                new_subs.map(|ok| Policy::Threshold(k, ok))
            }
            Policy::And(ref subs) => Ok(Policy::And(
                subs.iter()
                    .map(|sub| sub.translate_pk(&mut translatefpk, &mut translatefpkh))
                    .collect::<Result<Vec<Policy<Q>>, E>>()?
            )),
            Policy::Or(ref subs) => Ok(Policy::Or(
                subs.iter()
                    .map(|&(ref prob, ref sub)|
                         Ok((*prob, sub.translate_pk(&mut translatefpk, &mut translatefpkh)?))
                    )
                    .collect::<Result<Vec<(usize, Policy<Q>)>, E>>()?
            )),
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for Policy<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Policy::Key(ref pk) => write!(f, "pk({:?})", pk),
            Policy::KeyHash(ref pkh) => write!(f, "pkh({:?})", pkh),
            Policy::After(n) => write!(f, "after({})", n),
            Policy::Older(n) => write!(f, "older({})", n),
            Policy::Sha256(h) => write!(f, "sha256({})", h),
            Policy::Hash256(h) => write!(f, "hash256({})", h),
            Policy::Ripemd160(h) => write!(f, "ripemd160({})", h),
            Policy::Hash160(h) => write!(f, "hash160({})", h),
            Policy::And(ref subs) => {
                f.write_str("and(")?;
                if !subs.is_empty() {
                    write!(f, "{:?}", subs[0])?;
                    for sub in &subs[1..] {
                        write!(f, ",{:?}", sub)?;
                    }
                }
                f.write_str(")")
            },
            Policy::Or(ref subs) => {
                f.write_str("or(")?;
                if !subs.is_empty() {
                    write!(f, "{}@{:?}", subs[0].0, subs[0].1)?;
                    for sub in &subs[1..] {
                        write!(f, ",{}@{:?}", sub.0, sub.1)?;
                    }
                }
                f.write_str(")")
            },
            Policy::Threshold(k, ref subs) => {
                write!(f, "thresh({}", k)?;
                for sub in subs {
                    write!(f, ",{:?}", sub)?;
                }
                f.write_str(")")
            }
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Policy<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Policy::Key(ref pk) => write!(f, "pk({})", pk),
            Policy::KeyHash(ref pkh) => write!(f, "pkh({})", pkh),
            Policy::After(n) => write!(f, "after({})", n),
            Policy::Older(n) => write!(f, "older({})", n),
            Policy::Sha256(h) => write!(f, "sha256({})", h),
            Policy::Hash256(h) => write!(f, "hash256({})", h),
            Policy::Ripemd160(h) => write!(f, "ripemd160({})", h),
            Policy::Hash160(h) => write!(f, "hash160({})", h),
            Policy::And(ref subs) => {
                f.write_str("and(")?;
                if !subs.is_empty() {
                    write!(f, "{}", subs[0])?;
                    for sub in &subs[1..] {
                        write!(f, ",{}", sub)?;
                    }
                }
                f.write_str(")")
            },
            Policy::Or(ref subs) => {
                f.write_str("or(")?;
                if !subs.is_empty() {
                    write!(f, "{}@{}", subs[0].0, subs[0].1)?;
                    for sub in &subs[1..] {
                        write!(f, ",{}@{}", sub.0, sub.1)?;
                    }
                }
                f.write_str(")")
            },
            Policy::Threshold(k, ref subs) => {
                write!(f, "thresh({}", k)?;
                for sub in subs {
                    write!(f, ",{}", sub)?;
                }
                f.write_str(")")
            }
        }
    }
}

impl<Pk> str::FromStr for Policy<Pk> where
    Pk: MiniscriptKey,
    <Pk as str::FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as str::FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Policy<Pk>, Error> {
        for ch in s.as_bytes() {
            if *ch < 20 || *ch > 127 {
                return Err(Error::Unprintable(*ch));
            }
        }

        let tree = expression::Tree::from_str(s)?;
        FromTree::from_tree(&tree)
    }
}

impl<Pk> Policy<Pk> where
    Pk: MiniscriptKey,
    <Pk as str::FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as str::FromStr>::Err: ToString,
{
    /// Helper function for `from_tree` to parse subexpressions with
    /// names of the form x@y
    fn from_tree_prob(
        top: &expression::Tree,
        allow_prob: bool,
    ) -> Result<(usize, Policy<Pk>), Error> {
        let frag_prob;
        let frag_name;
        let mut name_split = top.name.split('@');
        match (name_split.next(), name_split.next(), name_split.next()) {
            (None, _, _) => {
                frag_prob = 1;
                frag_name = "";
            },
            (Some(name), None, _) => {
                frag_prob = 1;
                frag_name = name;
            },
            (Some(prob), Some(name), None) => {
                if !allow_prob {
                    return Err(Error::AtOutsideOr(top.name.to_owned()));
                }
                frag_prob = expression::parse_num(prob)? as usize;
                frag_name = name;
            },
            (Some(_), Some(_), Some(_)) => {
                return Err(Error::MultiColon(top.name.to_owned()));
            },
        }
        match (frag_name, top.args.len() as u32) {
            ("pk", 1) => expression::terminal(
                &top.args[0],
                |pk| Pk::from_str(pk).map(Policy::Key)
            ),
            ("pkh", 1) => expression::terminal(
                &top.args[0],
                |pk| Pk::Hash::from_str(pk).map(Policy::KeyHash)
            ),
            ("after", 1) => {
                expression::terminal(
                    &top.args[0],
                    |x| expression::parse_num(x).map(Policy::After)
                )
            },
            ("older", 1) => {
                expression::terminal(
                    &top.args[0],
                    |x| expression::parse_num(x).map(Policy::Older)
                )
            },
            ("sha256", 1) => {
                expression::terminal(
                    &top.args[0],
                    |x| sha256::Hash::from_hex(x).map(Policy::Sha256)
                )
            },
            ("hash256", 1) => {
                expression::terminal(
                    &top.args[0],
                    |x| sha256d::Hash::from_hex(x).map(Policy::Hash256)
                )
            },
            ("ripemd160", 1) => {
                expression::terminal(
                    &top.args[0],
                    |x| ripemd160::Hash::from_hex(x).map(Policy::Ripemd160)
                )
            },
            ("hash160", 1) => {
                expression::terminal(
                    &top.args[0],
                    |x| hash160::Hash::from_hex(x).map(Policy::Hash160)
                )
            },
            ("and", _) => {
                if top.args.is_empty() {
                    return Err(errstr("and without args"));
                }
                let mut subs = Vec::with_capacity(top.args.len());
                for arg in &top.args {
                    subs.push(Policy::from_tree(arg)?);
                }
                Ok(Policy::And(subs))
            },
            ("or", _) => {
                if top.args.is_empty() {
                    return Err(errstr("or without args"));
                }
                let mut subs = Vec::with_capacity(top.args.len());
                for arg in &top.args {
                    subs.push(Policy::from_tree_prob(arg, true)?);
                }
                Ok(Policy::Or(subs))
            },
            ("thresh", nsubs) => {
                if !top.args[0].args.is_empty() {
                    return Err(errstr(top.args[0].args[0].name));
                }

                let thresh = expression::parse_num(top.args[0].name)?;
                if thresh >= nsubs {
                    return Err(errstr(top.args[0].name));
                }

                let mut subs = Vec::with_capacity(top.args.len() - 1);
                for arg in &top.args[1..] {
                    subs.push(Policy::from_tree(arg)?);
                }
                Ok(Policy::Threshold(thresh as usize, subs))
            }
            _ => Err(errstr(top.name))
        }.map(|res| (frag_prob, res))
    }
}

impl<Pk> FromTree for Policy<Pk> where
    Pk: MiniscriptKey,
    <Pk as str::FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as str::FromStr>::Err: ToString,
{
    fn from_tree(top: &expression::Tree) -> Result<Policy<Pk>, Error> {
        Policy::from_tree_prob(top, false).map(|(_, result)| result)
    }
}
