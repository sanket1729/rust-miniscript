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

//! Miniscript and Output Descriptors
//!
//! # Introduction
//! ## Bitcoin Script
//!
//! In Bitcoin, spending policies are defined and enforced by means of a
//! stack-based programming language known as Bitcoin Script. While this
//! language appears to be designed with tractable analysis in mind (e.g.
//! there are no looping or jumping constructions), in practice this is
//! extremely difficult. As a result, typical wallet software supports only
//! a small set of script templates, cannot interoperate with other similar
//! software, and each wallet contains independently written ad-hoc manually
//! verified code to handle these templates. Users who require more complex
//! spending policies, or who want to combine signing infrastructure which
//! was not explicitly designed to work together, are simply out of luck.
//!
//! ## Miniscript
//!
//! Miniscript is an alternative to Bitcoin Script which eliminates these
//! problems. It can be efficiently and simply encoded as Script to ensure
//! that it works on the Bitcoin blockchain, but its design is very different.
//! Essentially, a Miniscript is a monotone function (tree of ANDs, ORs and
//! thresholds) of signature requirements, hash preimage requirements, and
//! timelocks.
//!
//! A [full description of Miniscript is available here](http://bitcoin.sipa.be/miniscript/miniscript.html).
//!
//! Miniscript also admits a more human-readable encoding.
//!
//! ## Output Descriptors
//!
//! While spending policies in Bitcoin are entirely defined by Script; there
//! are multiple ways of embedding these Scripts in transaction outputs; for
//! example, P2SH or Segwit v0. These different embeddings are expressed by
//! *Output Descriptors*, [which are described here](https://github.com/bitcoin/bitcoin/blob/master/doc/descriptors.md)
//!
//! # Examples
//!
//! ## Deriving an address from a descriptor
//!
//! ```rust
//! extern crate bitcoin;
//! extern crate bitcoin_hashes;
//! extern crate miniscript;
//!
//! use std::str::FromStr;
//!
//! fn main() {
//!     let desc = miniscript::Descriptor::<
//!         bitcoin::PublicKey,
//!         miniscript::DummyKeyHash,
//!     >::from_str("\
//!         sh(wsh(or_d(\
//!             c:pk(020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261),\
//!             c:pk(020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261)\
//!         )))\
//!     ").unwrap();
//!
//!     // Derive the P2SH address
//!     assert_eq!(
//!         desc.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
//!         "32aAVauGwencZwisuvd3anhhhQhNZQPyHv"
//!     );
//!
//!     // Estimate the satisfaction cost
//!     assert_eq!(desc.max_satisfaction_weight(), 293);
//! }
//! ```
//!

#![cfg_attr(all(test, feature = "unstable"), feature(test))]
#[cfg(all(test, feature = "unstable"))] extern crate test;

extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate secp256k1;
#[cfg(feature="serde")] extern crate serde;

pub mod miniscript;
pub mod descriptor;
pub mod expression;
pub mod policy;
pub mod psbt;

use std::{error, fmt, str};

use bitcoin::blockdata::{opcodes, script};
use bitcoin_hashes::{Hash, hash160, sha256};

pub use miniscript::astelem::AstElem;
pub use descriptor::Descriptor;
pub use miniscript::Miniscript;
pub use miniscript::satisfy::{BitcoinSig, Satisfier};

/// Trait describing public key types which can be converted to bitcoin pubkeys
pub trait ToPublicKey {
    /// Converts an object to a public key
    fn to_public_key(&self) -> bitcoin::PublicKey;

    /// Computes the size of a public key when serialized in a script,
    /// including the length bytes
    fn serialized_len(&self) -> usize {
        if self.to_public_key().compressed {
            34
        } else {
            66
        }
    }
}

impl ToPublicKey for bitcoin::PublicKey {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        *self
    }
}

/// Trait describing public keyhash types which can be converted to hash160 hashes
pub trait ToPublicKeyHash {
    /// Converts an object to a keyhash
    fn to_public_key_hash(&self) -> hash160::Hash;
}

impl ToPublicKeyHash for hash160::Hash {
    fn to_public_key_hash(&self) -> hash160::Hash {
        *self
    }
}

impl ToPublicKeyHash for bitcoin::PublicKey {
    fn to_public_key_hash(&self) -> hash160::Hash {
        let mut engine = hash160::Hash::engine();
        self.write_into(&mut engine);
        hash160::Hash::from_engine(engine)
    }
}


/// Dummy key which de/serializes to the empty string; useful sometimes for testing
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Debug)]
pub struct DummyKey;

impl str::FromStr for DummyKey {
    type Err = &'static str;
    fn from_str(x: &str) -> Result<DummyKey, &'static str> {
        if x.is_empty() {
            Ok(DummyKey)
        } else {
            Err("non empty dummy key")
        }
    }
}

impl fmt::Display for DummyKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("")
    }
}

impl ToPublicKey for DummyKey {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        use std::str::FromStr;
        bitcoin::PublicKey::from_str("020102030405060708010203040506070801020304050607080102030405060708").unwrap()
    }
}

/// Dummy keyhash which de/serializes to the empty string; useful sometimes for testing
#[derive(Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Debug)]
pub struct DummyKeyHash;

impl str::FromStr for DummyKeyHash {
    type Err = &'static str;
    fn from_str(x: &str) -> Result<DummyKeyHash, &'static str> {
        if x.is_empty() {
            Ok(DummyKeyHash)
        } else {
            Err("non empty dummy key")
        }
    }
}

impl fmt::Display for DummyKeyHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("")
    }
}

impl ToPublicKeyHash for DummyKeyHash {
    fn to_public_key_hash(&self) -> hash160::Hash {
        use bitcoin_hashes::hex::FromHex;
        hash160::Hash::from_hex("0000000000000000000000000000000000000000").unwrap()
    }
}

/// Miniscript
#[derive(Debug)]
pub enum Error {
    /// Opcode appeared which is not part of the script subset
    InvalidOpcode(opcodes::All),
    /// Some opcode occured followed by `OP_VERIFY` when it had
    /// a `VERIFY` version that should have been used instead
    NonMinimalVerify(miniscript::lex::Token),
    /// Push was illegal in some context
    InvalidPush(Vec<u8>),
    /// PSBT-related error
    Psbt(psbt::Error),
    /// rust-bitcoin script error
    Script(script::Error),
    /// A `CHECKMULTISIG` opcode was preceded by a number > 20
    CmsTooManyKeys(u32),
    /// Encountered unprintable character in descriptor
    Unprintable(u8),
    /// expected character while parsing descriptor; didn't find one
    ExpectedChar(char),
    /// While parsing backward, hit beginning of script
    UnexpectedStart,
    /// Got something we were not expecting
    Unexpected(String),
    /// Name of a fragment contained `:` multiple times
    MultiColon(String),
    /// Name of a fragment contained `@` multiple times
    MultiAt(String),
    /// Name of a fragment contained `@` but we were not parsing an OR
    AtOutsideOr(String),
    /// Fragment was an `and_v(_, true())` which should be written as `t:`
    NonCanonicalTrue,
    /// Encountered a wrapping character that we don't recognize
    UnknownWrapper(char),
    /// Parsed a miniscript and the result was not of type T
    NonTopLevel(String),
    /// Parsed a miniscript but there were more script opcodes after it
    Trailing(String),
    /// Failed to parse a push as a public key
    BadPubkey(bitcoin::consensus::encode::Error),
    /// Could not satisfy a script (fragment) because of a missing hash preimage
    MissingHash(sha256::Hash),
    /// Could not satisfy a script (fragment) because of a missing signature
    MissingSig(bitcoin::PublicKey),
    /// Could not satisfy, relative locktime not met
    RelativeLocktimeNotMet(u32),
    /// Could not satisfy, absolute locktime not met
    AbsoluteLocktimeNotMet(u32),
    /// General failure to satisfy
    CouldNotSatisfy,
    /// Typechecking failed
    TypeCheck(String),
    ///General error in creating descriptor
    BadDescriptor,
    ///Forward-secp related errors
    Secp(secp256k1::Error),
    ///Interpreter related errors
    InterpreterError(descriptor::satisfied_contraints::Error),
    /// Bad Script Sig. As per standardness rules, only pushes are allowed in
    /// scriptSig. This error is invoked when op_codes are pushed onto the stack
    /// As per the current implementation, pushing an integer apart from 0 or 1
    /// will also trigger this. This is because, Miniscript only expects push
    /// bytes for pk, sig, preimage etc or 1 or 0 for `StackElement::Satisfied`
    /// or `StackElement::Dissatisfied`
    BadScriptSig,
    ///Witness must be empty for pre-segwit transactions
    NonEmptyWitness,
    ///ScriptSig must be empty for pure segwit transactions
    NonEmptyScriptSig,
    ///Incorrect Script pubkey Hash for the descriptor. This is used for both
    /// `PkH` and `Wpkh` descriptors
    IncorrectPubkeyHash,
    ///Incorrect Script pubkey Hash for the descriptor. This is used for both
    /// `Sh` and `Wsh` descriptors
    IncorrectScriptHash,
}

#[doc(hidden)]
impl<Pk, Pkh> From<miniscript::types::Error<Pk, Pkh>> for Error
where
    Pk: Clone + fmt::Debug + fmt::Display,
    Pkh: Clone + fmt::Debug + fmt::Display,
{
    fn from(e: miniscript::types::Error<Pk, Pkh>) -> Error {
        Error::TypeCheck(e.to_string())
    }
}

fn errstr(s: &str) -> Error {
    Error::Unexpected(s.to_owned())
}

impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::BadPubkey(ref e) => Some(e),
//            Error::Psbt(ref e) => Some(e),
            _ => None,
        }
    }

    fn description(&self) -> &str {
        ""
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidOpcode(op) => write!(f, "invalid opcode {}", op),
            Error::NonMinimalVerify(tok) => write!(f, "{} VERIFY", tok),
            Error::InvalidPush(ref push) =>
                write!(f, "invalid push {:?}", push), // TODO hexify this
            Error::Psbt(ref e) => fmt::Display::fmt(e, f),
            Error::Script(ref e) => fmt::Display::fmt(e, f),
            Error::CmsTooManyKeys(n)
                => write!(f, "checkmultisig with {} keys", n),
            Error::Unprintable(x)
                => write!(f, "unprintable character 0x{:02x}", x),
            Error::ExpectedChar(c) => write!(f, "expected {}", c),
            Error::UnexpectedStart => f.write_str("unexpected start of script"),
            Error::Unexpected(ref s) => write!(f, "unexpected «{}»", s),
            Error::MultiColon(ref s)
                => write!(f, "«{}» has multiple instances of «:»", s),
            Error::MultiAt(ref s)
                => write!(f, "«{}» has multiple instances of «@»", s),
            Error::AtOutsideOr(ref s)
                => write!(f, "«{}» contains «@» in non-or() context", s),
            Error::NonCanonicalTrue
                => f.write_str("Use «t:X» rather than «and_v(X,true())»"),
            Error::UnknownWrapper(ch) => write!(f, "unknown wrapper «{}:»", ch),
            Error::NonTopLevel(ref s) => write!(f, "non-T miniscript: {}", s),
            Error::Trailing(ref s) => write!(f, "trailing tokens: {}", s),
            Error::MissingHash(ref h) => write!(f, "missing preimage of hash {}", h),
            Error::MissingSig(ref pk) => write!(f, "missing signature for key {:?}", pk),
            Error::RelativeLocktimeNotMet(n) => write!(f, "required relative locktime CSV of {} blocks, not met", n),
            Error::AbsoluteLocktimeNotMet(n) => write!(f, "required absolute locktime CLTV of {} blocks, not met", n),
            Error::CouldNotSatisfy => f.write_str("could not satisfy"),
            Error::BadPubkey(ref e) => fmt::Display::fmt(e, f),
            Error::TypeCheck(ref e) => write!(f, "typecheck: {}", e),
            Error::BadDescriptor => f.write_str("could not create a descriptor"),
            Error::Secp(ref e) => fmt::Display::fmt(e, f),
            Error::InterpreterError(ref e) => fmt::Display::fmt(e, f),
            Error::BadScriptSig =>
                f.write_str("Script sig must only consist of pushes"),
            Error::NonEmptyWitness =>
                f.write_str("Non empty witness for Pk/Pkh"),
            Error::NonEmptyScriptSig =>
                f.write_str("Non empty script sig for segwit spend"),
            Error::IncorrectScriptHash =>
                f.write_str("Incorrect script hash for redeem script sh/wsh"),
            Error::IncorrectPubkeyHash =>
                f.write_str("Incorrect pubkey hash for given descriptor pkh/wpkh"),
        }
    }
}

#[doc(hidden)]
impl From<psbt::Error> for Error {
    fn from(e: psbt::Error) -> Error {
        Error::Psbt(e)
    }
}

/// The size of an encoding of a number in Script
pub fn script_num_size(n: usize) -> usize {
    match n {
        n if n <= 0x10 => 1,  // OP_n
        n if n < 0x80 => 2,  // OP_PUSH1 <n>
        n if n < 0x8000 => 3, // OP_PUSH2 <n>
        n if n < 0x800000 => 4, // OP_PUSH3 <n>
        n if n < 0x80000000 => 5, // OP_PUSH4 <n>
        _ => 6, // OP_PUSH5 <n>
    }
}

/// Helper function used by tests
#[cfg(test)]
fn hex_script(s: &str) -> bitcoin::Script {
    let v: Vec<u8> = bitcoin_hashes::hex::FromHex::from_hex(s).unwrap();
    bitcoin::Script::from(v)
}
