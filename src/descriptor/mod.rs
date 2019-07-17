// Miniscript
// Written in 2018 by
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

//! # Output Descriptors
//!
//! Tools for representing Bitcoin output's scriptPubKeys as abstract spending
//! policies known as "output descriptors". These include a Miniscript which
//! describes the actual signing policy, as well as the blockchain format (P2SH,
//! Segwit v0, etc.)
//!
//! The format represents EC public keys abstractly to allow wallets to replace
//! these with BIP32 paths, pay-to-contract instructions, etc.
//!

use bitcoin::{self, Script};
use bitcoin::blockdata::{opcodes, script};
#[cfg(feature = "serde")] use serde::{de, ser};
use std::fmt;
use std::str::{self, FromStr};

use expression;
use miniscript::Miniscript;
use Error;
//use miniscript::satisfy::Satisfier;
use Satisfier;
use ToPublicKey;
use ToPublicKeyHash;

/// Script descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Descriptor<Pk, Pkh> {
    /// A raw scriptpubkey (including pay-to-pubkey)
    Bare(Miniscript<Pk, Pkh>),
    /// Pay-to-Pubkey
    Pk(Pk),
    /// Pay-to-PubKey-Hash
    Pkh(Pk),
    /// Pay-to-Witness-PubKey-Hash
    Wpkh(Pk),
    /// Pay-to-Witness-PubKey-Hash inside P2SH
    ShWpkh(Pk),
    /// Pay-to-ScriptHash
    Sh(Miniscript<Pk, Pkh>),
    /// Pay-to-Witness-ScriptHash
    Wsh(Miniscript<Pk, Pkh>),
    /// P2SH-P2WSH
    ShWsh(Miniscript<Pk, Pkh>),
}

impl<Pk, Pkh: Clone> Descriptor<Pk, Pkh> {
    /// Convert a descriptor using abstract keys to one using specific keys
    pub fn translate_pk<F, Q, E>(
        &self,
        mut translatefn: F,
    ) -> Result<Descriptor<Q, Pkh>, E> where F: FnMut(&Pk) -> Result<Q, E> {
        match *self {
            Descriptor::Bare(ref descript) => {
                Ok(Descriptor::Bare(descript.translate_pk(translatefn)?))
            },
            Descriptor::Pk(ref pk) => translatefn(pk).map(Descriptor::Pk),
            Descriptor::Pkh(ref pk) => translatefn(pk).map(Descriptor::Pkh),
            Descriptor::Wpkh(ref pk) => translatefn(pk).map(Descriptor::Wpkh),
            Descriptor::ShWpkh(ref pk) =>
                translatefn(pk).map(Descriptor::ShWpkh),
            Descriptor::Sh(ref descript) => {
                Ok(Descriptor::Sh(descript.translate_pk(translatefn)?))
            }
            Descriptor::Wsh(ref descript) => {
                Ok(Descriptor::Wsh(descript.translate_pk(translatefn)?))
            }
            Descriptor::ShWsh(ref descript) => {
                Ok(Descriptor::ShWsh(descript.translate_pk(translatefn)?))
            }
        }
    }
}

impl<Pk: ToPublicKey, Pkh: ToPublicKeyHash> Descriptor<Pk, Pkh> {
    /// Computes the Bitcoin address of the descriptor, if one exists
    pub fn address(&self, network: bitcoin::Network)
        -> Option<bitcoin::Address>
    {
        match *self {
            Descriptor::Bare(..) => None,
            Descriptor::Pk(..) => None,
            Descriptor::Pkh(ref pk) => {
                Some(bitcoin::Address::p2pkh(
                    &pk.to_public_key(),
                    network,
                ))
            },
            Descriptor::Wpkh(ref pk) => {
                Some(bitcoin::Address::p2wpkh(
                    &pk.to_public_key(),
                    network,
                ))
            },
            Descriptor::ShWpkh(ref pk) => {
                Some(bitcoin::Address::p2shwpkh(
                    &pk.to_public_key(),
                    network,
                ))
            },
            Descriptor::Sh(ref miniscript) => {
                Some(bitcoin::Address::p2sh(
                    &miniscript.encode(),
                    network,
                ))
            },
            Descriptor::Wsh(ref miniscript) => {
                Some(bitcoin::Address::p2wsh(
                    &miniscript.encode(),
                    network,
                ))
            },
            Descriptor::ShWsh(ref miniscript) => {
                Some(bitcoin::Address::p2shwsh(
                    &miniscript.encode(),
                    network,
                ))
            },
        }
    }

    /// Computes the scriptpubkey of the descriptor
    pub fn script_pubkey(&self) -> Script {
        match *self {
            Descriptor::Bare(ref d) => d.encode(),
            Descriptor::Pk(ref pk) => {
                script::Builder::new()
                    .push_key(&pk.to_public_key())
                    .push_opcode(opcodes::all::OP_CHECKSIG)
                    .into_script()
            },
            Descriptor::Pkh(ref pk) => {
                let addr = bitcoin::Address::p2pkh(
                    &pk.to_public_key(),
                    bitcoin::Network::Bitcoin,
                );
                addr.script_pubkey()
            },
            Descriptor::Wpkh(ref pk) => {
                let addr = bitcoin::Address::p2wpkh(
                    &pk.to_public_key(),
                    bitcoin::Network::Bitcoin,
                );
                addr.script_pubkey()
            },
            Descriptor::ShWpkh(ref pk) => {
                let addr = bitcoin::Address::p2shwpkh(
                    &pk.to_public_key(),
                    bitcoin::Network::Bitcoin,
                );
                addr.script_pubkey()
            },
            Descriptor::Sh(ref miniscript) => miniscript.encode().to_p2sh(),
            Descriptor::Wsh(ref miniscript) => miniscript
                .encode()
                .to_v0_p2wsh(),
            Descriptor::ShWsh(ref miniscript) => miniscript
                .encode()
                .to_v0_p2wsh()
                .to_p2sh(),
        }
    }

    /// Computes the scriptSig that will be in place for an unsigned
    /// input spending an output with this descriptor. For pre-segwit
    /// descriptors, which use the scriptSig for signatures, this
    /// returns the empty script.
    ///
    /// This is used in Segwit transactions to produce an unsigned
    /// transaction whose txid will not change during signing (since
    /// only the witness data will change).
    pub fn unsigned_script_sig(&self) -> Script {
        match *self {
            // non-segwit
            Descriptor::Bare(..)
                | Descriptor::Pk(..)
                | Descriptor::Pkh(..)
                | Descriptor::Sh(..) => Script::new(),
            // pure segwit, empty scriptSig
            Descriptor::Wsh(..) |
            Descriptor::Wpkh(..) => Script::new(),
            // segwit+p2sh
            Descriptor::ShWpkh(ref pk) => {
                let addr = bitcoin::Address::p2wpkh(
                    &pk.to_public_key(),
                    bitcoin::Network::Bitcoin,
                );
                let redeem_script = addr.script_pubkey();
                script::Builder::new()
                    .push_slice(&redeem_script[..])
                    .into_script()
            },
            Descriptor::ShWsh(ref d) => {
                let witness_script = d.encode();
                script::Builder::new()
                    .push_slice(&witness_script.to_v0_p2wsh()[..])
                    .into_script()
            },
        }
    }

    /// Computes the "witness script" of the descriptor, i.e. the underlying
    /// script before any hashing is done. For `Bare`, `Pkh` and `Wpkh` this
    /// is the scriptPubkey; for `ShWpkh` and `Sh` this is the redeemScript;
    /// for the others it is the witness script.
    pub fn witness_script(&self) -> Script {
        match *self {
            Descriptor::Bare(..)
                | Descriptor::Pk(..)
                | Descriptor::Pkh(..)
                | Descriptor::Wpkh(..) => self.script_pubkey(),
            Descriptor::ShWpkh(ref pk) => {
                let addr = bitcoin::Address::p2wpkh(
                    &pk.to_public_key(),
                    bitcoin::Network::Bitcoin,
                );
                addr.script_pubkey()
            }
            Descriptor::Sh(ref d) |
            Descriptor::Wsh(ref d) |
            Descriptor::ShWsh(ref d) => d.encode(),
        }
    }

    /// Attempts to produce a satisfying witness and scriptSig to spend an
    /// output controlled by the given descriptor; add the data to a given
    /// `TxIn` output.
    pub fn satisfy<S: Satisfier<Pk, Pkh>>(
        &self,
        txin: &mut bitcoin::TxIn,
        satisfier: &S,
        age: u32,
        height: u32,
    ) -> Result<(), Error> {
        fn witness_to_scriptsig(witness: &[Vec<u8>]) -> Script {
            let mut b = script::Builder::new();
            for wit in witness {
                if let Ok(n) = script::read_scriptint(wit) {
                    b = b.push_int(n);
                } else {
                    b = b.push_slice(wit);
                }
            }
            b.into_script()
        }

        match *self {
            Descriptor::Bare(ref d) => {
                let wit = match d.satisfy(satisfier, age, height) {
                    Some(wit) => wit,
                    None => return Err(Error::CouldNotSatisfy),
                };
                txin.script_sig = witness_to_scriptsig(&wit);
                txin.witness = vec![];
                Ok(())
            },
            Descriptor::Pk(ref pk) => {
                if let Some(vec) = satisfier.lookup_pk_vec(pk) {
                    txin.script_sig = script::Builder::new()
                        .push_slice(&vec)
                        .into_script();
                    txin.witness = vec![];
                    Ok(())
                } else {
                    Err(Error::MissingSig(pk.to_public_key()))
                }
            },
            Descriptor::Pkh(ref pk) => {
                if let Some(vec) = satisfier.lookup_pk_vec(pk) {
                    txin.script_sig = script::Builder::new()
                        .push_slice(&vec)
                        .push_key(&pk.to_public_key())
                        .into_script();
                    txin.witness = vec![];
                    Ok(())
                } else {
                    Err(Error::MissingSig(pk.to_public_key()))
                }
            },
            Descriptor::Wpkh(ref pk) => {
                if let Some(vec) = satisfier.lookup_pk_vec(pk) {
                    txin.script_sig = Script::new();
                    txin.witness = vec![vec, pk.to_public_key().to_bytes()];
                    Ok(())
                } else {
                    Err(Error::MissingSig(pk.to_public_key()))
                }
            },
            Descriptor::ShWpkh(ref pk) => {
                if let Some(vec) = satisfier.lookup_pk_vec(pk) {
                    let addr = bitcoin::Address::p2wpkh(
                        &pk.to_public_key(),
                        bitcoin::Network::Bitcoin,
                    );
                    let redeem_script = addr.script_pubkey();

                    txin.script_sig = script::Builder::new()
                        .push_slice(&redeem_script[..])
                        .into_script();
                    txin.witness = vec![vec, pk.to_public_key().to_bytes()];
                    Ok(())
                } else {
                    Err(Error::MissingSig(pk.to_public_key()))
                }
            },
            Descriptor::Sh(ref d) => {
                let mut witness = match d.satisfy(satisfier, age, height) {
                    Some(wit) => wit,
                    None => return Err(Error::CouldNotSatisfy),
                };
                witness.push(d.encode().into_bytes());
                txin.script_sig = witness_to_scriptsig(&witness);
                txin.witness = vec![];
                Ok(())
            },
            Descriptor::Wsh(ref d) => {
                let mut witness = match d.satisfy(satisfier, age, height) {
                    Some(wit) => wit,
                    None => return Err(Error::CouldNotSatisfy),
                };
                witness.push(d.encode().into_bytes());
                txin.script_sig = Script::new();
                txin.witness = witness;
                Ok(())
            },
            Descriptor::ShWsh(ref d) => {
                let witness_script = d.encode();
                txin.script_sig = script::Builder::new()
                    .push_slice(&witness_script.to_v0_p2wsh()[..])
                    .into_script();

                let mut witness = match d.satisfy(satisfier, age, height) {
                    Some(wit) => wit,
                    None => return Err(Error::CouldNotSatisfy),
                };
                witness.push(witness_script.into_bytes());
                txin.witness = witness;
                Ok(())
            },
        }
    }

    /// Computes an upper bound on the weight of a satisfying witness to the
    /// transaction. Assumes all signatures are 73 bytes, including push opcode
    /// and sighash suffix. Includes the weight of the VarInts encoding the
    /// scriptSig and witness stack length.
    pub fn max_satisfaction_weight(&self) -> usize {
        fn varint_len(n: usize) -> usize {
            bitcoin::VarInt(n as u64).encoded_length() as usize
        }

        match *self {
            Descriptor::Bare(ref ms) => {
                let scriptsig_len = ms.max_satisfaction_size(1);
                4 * (varint_len(scriptsig_len) + scriptsig_len)
            },
            Descriptor::Pk(..) => 4 * (1 + 73),
            Descriptor::Pkh(ref pk) => 4 * (1 + 73 + pk.serialized_len()),
            Descriptor::Wpkh(ref pk) => 4 + 1 + 73 + pk.serialized_len(),
            Descriptor::ShWpkh(ref pk) => 4 * 24 + 1 + 73 + pk.serialized_len(),
            Descriptor::Sh(ref ms) => {
                let ss = ms.script_size();
                let push_size = if ss < 76 {
                    1
                } else if ss < 0x100 {
                    2
                } else if ss < 0x10000 {
                    3
                } else {
                    5
                };

                let scriptsig_len = push_size + ss + ms.max_satisfaction_size(1);
                4 * (varint_len(scriptsig_len) + scriptsig_len)
            },
            Descriptor::Wsh(ref ms) => {
                let script_size = ms.script_size();
                4 +  // scriptSig length byte
                    varint_len(script_size) +
                    script_size +
                    varint_len(ms.max_satisfaction_witness_elements()) +
                    ms.max_satisfaction_size(2)
            },
            Descriptor::ShWsh(ref ms) => {
                let script_size = ms.script_size();
                4 * 36 +
                    varint_len(script_size) +
                    script_size +
                    varint_len(ms.max_satisfaction_witness_elements()) +
                    ms.max_satisfaction_size(2)
            },
        }
    }
}

impl<Pk, Pkh> expression::FromTree for Descriptor<Pk, Pkh> where
    Pk: Clone + fmt::Debug + fmt::Display + str::FromStr,
    Pkh: Clone + fmt::Debug + fmt::Display + str::FromStr,
    <Pk as FromStr>::Err: ToString,
    <Pkh as FromStr>::Err: ToString,
{
    /// Parse an expression tree into a descriptor
    fn from_tree(top: &expression::Tree) -> Result<Descriptor<Pk, Pkh>, Error> {
        match (top.name, top.args.len() as u32) {
            ("pk", 1) => expression::terminal(
                &top.args[0],
                |pk| Pk::from_str(pk).map(Descriptor::Pk),
            ),
            ("pkh", 1) => expression::terminal(
                &top.args[0],
                |pk| Pk::from_str(pk).map(Descriptor::Pkh),
            ),
            ("wpkh", 1) => expression::terminal(
                &top.args[0],
                |pk| Pk::from_str(pk).map(Descriptor::Wpkh),
            ),
            ("sh", 1) => {
                let newtop = &top.args[0];
                match (newtop.name, newtop.args.len()) {
                    ("wsh", 1) => {
                        let sub = Miniscript::from_tree(&newtop.args[0])?;
                        Ok(Descriptor::ShWsh(sub))
                    }
                    ("wpkh", 1) => expression::terminal(
                        &newtop.args[0],
                        |pk| Pk::from_str(pk).map(Descriptor::ShWpkh)
                    ),
                    _ => {
                        let sub = Miniscript::from_tree(&top.args[0])?;
                        Ok(Descriptor::Sh(sub))
                    }
                }
            }
            ("wsh", 1) => expression::unary(top, Descriptor::Wsh),
            _ => {
                let sub = expression::FromTree::from_tree(&top)?;
                Ok(Descriptor::Bare(sub))
            }
        }
    }
}

impl<Pk, Pkh> FromStr for Descriptor<Pk, Pkh> where
    Pk: Clone + fmt::Debug + fmt::Display + str::FromStr,
    Pkh: Clone + fmt::Debug + fmt::Display + str::FromStr,
    <Pk as FromStr>::Err: ToString,
    <Pkh as FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Descriptor<Pk, Pkh>, Error> {
        for ch in s.as_bytes() {
            if *ch < 20 || *ch > 127 {
                return Err(Error::Unprintable(*ch));
            }
        }

        let top = expression::Tree::from_str(s)?;
        expression::FromTree::from_tree(&top)
    }
}

impl <Pk, Pkh> fmt::Debug for Descriptor<Pk, Pkh>
where
    Pk: Clone + fmt::Debug,
    Pkh: Clone + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Descriptor::Bare(ref sub) => write!(f, "{:?}", sub),
            Descriptor::Pk(ref p) => write!(f, "pk({:?})", p),
            Descriptor::Pkh(ref p) => write!(f, "pkh({:?})", p),
            Descriptor::Wpkh(ref p) => write!(f, "wpkh({:?})", p),
            Descriptor::ShWpkh(ref p) => write!(f, "sh(wpkh({:?}))", p),
            Descriptor::Sh(ref sub) => write!(f, "sh({:?})", sub),
            Descriptor::Wsh(ref sub) => write!(f, "wsh({:?})", sub),
            Descriptor::ShWsh(ref sub) => write!(f, "sh(wsh({:?}))", sub),
        }
    }
}

impl <Pk, Pkh> fmt::Display for Descriptor<Pk, Pkh> where
    Pk: fmt::Display,
    Pkh: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Descriptor::Bare(ref sub) => write!(f, "{}", sub),
            Descriptor::Pk(ref p) => write!(f, "pk({})", p),
            Descriptor::Pkh(ref p) => write!(f, "pkh({})", p),
            Descriptor::Wpkh(ref p) => write!(f, "wpkh({})", p),
            Descriptor::ShWpkh(ref p) => write!(f, "sh(wpkh({}))", p),
            Descriptor::Sh(ref sub) => write!(f, "sh({})", sub),
            Descriptor::Wsh(ref sub) => write!(f, "wsh({})", sub),
            Descriptor::ShWsh(ref sub) => write!(f, "sh(wsh({}))", sub),
        }
    }
}

#[cfg(feature = "serde")]
impl<Pk, Pkh> ser::Serialize for Descriptor<Pk, Pkh> where
    Pk: fmt::Display,
    Pkh: fmt::Display,
{
    fn serialize<S: ser::Serializer>(&self, s: S)
        -> Result<S::Ok, S::Error>
    {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de, Pk, Pkh> de::Deserialize<'de> for Descriptor<Pk, Pkh> where
    Pk: fmt::Debug + str::FromStr,
    Pkh: fmt::Debug + str::FromStr,
    <Pk as str::FromStr>::Err: ToString,
    <Pkh as str::FromStr>::Err: ToString,
{
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Descriptor<Pk, Pkh>, D::Error> {
        use std::marker::PhantomData;

        struct StrVisitor<Qk, Qkh>(PhantomData<(Qk, Qkh)>);

        impl<'de, Qk, Qkh> de::Visitor<'de> for StrVisitor<Qk, Qkh> where
            Qk: fmt::Debug + str::FromStr,
            Qkh: fmt::Debug + str::FromStr,
            <Qk as str::FromStr>::Err: ToString,
            <Qkh as str::FromStr>::Err: ToString,
        {
            type Value = Descriptor<Qk, Qkh>;

            fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                fmt.write_str("an ASCII miniscript string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if let Ok(s) = str::from_utf8(v) {
                    Descriptor::from_str(s).map_err(E::custom)
                } else {
                    return Err(E::invalid_value(de::Unexpected::Bytes(v), &self));
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where
                E: de::Error,
            {
                Descriptor::from_str(v).map_err(E::custom)
            }
        }

        d.deserialize_str(StrVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{self, PublicKey};
    use bitcoin::blockdata::{opcodes, script};
    use bitcoin_hashes::{hash160, sha256};
    use bitcoin_hashes::hex::FromHex;
    use secp256k1;

    use std::str::FromStr;

    use miniscript::astelem;
    use miniscript::satisfy::BitcoinSig;
    use Miniscript;
    use descriptor::Descriptor;
    use DummyKeyHash;
    use miniscript::satisfy::Satisfier;
    use miniscript::types::Type;
    use miniscript::types::ExtData;
    use miniscript::types::Property;

    type StdDescriptor = Descriptor<PublicKey, DummyKeyHash>;
    const TEST_PK: &'static str = "pk(\
        020000000000000000000000000000000000000000000000000000000000000002\
    )";

    #[test]
    fn parse_descriptor() {
        StdDescriptor::from_str("(").unwrap_err();
        StdDescriptor::from_str("(x()").unwrap_err();
        StdDescriptor::from_str("(\u{7f}()3").unwrap_err();
        StdDescriptor::from_str("pk()").unwrap_err();

        StdDescriptor::from_str(TEST_PK).unwrap();
    }

    #[test]
    pub fn script_pubkey() {
        let bare = StdDescriptor::from_str("after(1000)").unwrap();
        assert_eq!(
            bare.script_pubkey(),
            bitcoin::Script::from(vec![0x02, 0xe8, 0x03, 0xb2])
        );
        assert_eq!(bare.address(bitcoin::Network::Bitcoin), None);

        let pk = StdDescriptor::from_str(TEST_PK).unwrap();
        assert_eq!(
            pk.script_pubkey(),
            bitcoin::Script::from(vec![
                0x21,
                0x02,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                0xac,
            ])
        );

        let pkh = StdDescriptor::from_str("pkh(\
            020000000000000000000000000000000000000000000000000000000000000002\
        )").unwrap();
        assert_eq!(
            pkh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash160::Hash::from_hex(
                    "84e9ed95a38613f0527ff685a9928abe2d4754d4",
                ).unwrap()[..])
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script()
        );
        assert_eq!(
            pkh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "1D7nRvrRgzCg9kYBwhPH3j3Gs6SmsRg3Wq"
        );

        let wpkh = StdDescriptor::from_str("wpkh(\
            020000000000000000000000000000000000000000000000000000000000000002\
        )").unwrap();
        assert_eq!(
            wpkh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                .push_slice(&hash160::Hash::from_hex(
                    "84e9ed95a38613f0527ff685a9928abe2d4754d4",
                ).unwrap()[..])
                .into_script()
        );
        assert_eq!(
            wpkh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "bc1qsn57m9drscflq5nl76z6ny52hck5w4x5wqd9yt"
        );

        let shwpkh = StdDescriptor::from_str("sh(wpkh(\
            020000000000000000000000000000000000000000000000000000000000000002\
        ))").unwrap();
        assert_eq!(
            shwpkh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash160::Hash::from_hex(
                    "f1c3b9a431134cb90a500ec06e0067cfa9b8bba7",
                ).unwrap()[..])
                .push_opcode(opcodes::all::OP_EQUAL)
                .into_script()
        );
        assert_eq!(
            shwpkh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "3PjMEzoveVbvajcnDDuxcJhsuqPHgydQXq"
        );

        let sh = StdDescriptor::from_str("sh(c:pk(\
            020000000000000000000000000000000000000000000000000000000000000002\
        ))").unwrap();
        assert_eq!(
            sh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash160::Hash::from_hex(
                    "aa5282151694d3f2f32ace7d00ad38f927a33ac8",
                ).unwrap()[..])
                .push_opcode(opcodes::all::OP_EQUAL)
                .into_script()
        );
        assert_eq!(
            sh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "3HDbdvM9CQ6ASnQFUkWw6Z4t3qNwMesJE9"
        );

        let wsh = StdDescriptor::from_str("wsh(c:pk(\
            020000000000000000000000000000000000000000000000000000000000000002\
        ))").unwrap();
        assert_eq!(
            wsh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_PUSHBYTES_0)
                .push_slice(&sha256::Hash::from_hex("\
                    f9379edc8983152dc781747830075bd5\
                    3896e4b0ce5bff73777fd77d124ba085\
                ").unwrap()[..])
                .into_script()
        );
        assert_eq!(
            wsh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "bc1qlymeahyfsv2jm3upw3urqp6m65ufde9seedl7umh0lth6yjt5zzsk33tv6"
        );

        let shwsh = StdDescriptor::from_str("sh(wsh(c:pk(\
            020000000000000000000000000000000000000000000000000000000000000002\
        )))").unwrap();
        assert_eq!(
            shwsh.script_pubkey(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(&hash160::Hash::from_hex(
                    "4bec5d7feeed99e1d0a23fe32a4afe126a7ff07e",
                ).unwrap()[..])
                .push_opcode(opcodes::all::OP_EQUAL)
                .into_script()
        );
        assert_eq!(
            shwsh.address(bitcoin::Network::Bitcoin).unwrap().to_string(),
            "38cTksiyPT2b1uGRVbVqHdDhW9vKs84N6Z"
        );
    }

    #[test]
    fn satisfy() {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(
            &b"sally was a secret key, she said"[..]
        ).unwrap();
        let pk = bitcoin::PublicKey {
            key: secp256k1::PublicKey::from_secret_key(&secp, &sk),
            compressed: true,
        };
        let msg = secp256k1::Message::from_slice(
            &b"michael was a message, amusingly"[..]
        ).expect("32 bytes");
        let sig = secp.sign(&msg, &sk);
        let mut sigser = sig.serialize_der();
        sigser.push(0x01); // sighash_all

        struct SimpleSat {
            sig: secp256k1::Signature,
            pk: bitcoin::PublicKey,
        };

        impl<Pkh> Satisfier<bitcoin::PublicKey, Pkh> for SimpleSat {
            fn lookup_pk(&self, pk: &bitcoin::PublicKey) -> Option<BitcoinSig> {
                if *pk == self.pk {
                    Some((self.sig, bitcoin::SigHashType::All))
                } else {
                    None
                }
            }
        }

        let satisfier = SimpleSat { sig, pk };
        let ms :Miniscript<_, DummyKeyHash> = Miniscript {
            node: astelem::AstElem::Check(Box::new(
                Miniscript {
                    node: astelem::AstElem::Pk(pk),
                    ty: Type::from_pk(),
                    ext: ExtData::from_pk()
                })),
            ty: Type::cast_check(Type::from_pk()).unwrap(),
            ext: ExtData::cast_check(ExtData::from_pk()).unwrap()
        };

        let mut txin = bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::default(),
            script_sig: bitcoin::Script::new(),
            sequence: 100,
            witness: vec![],
        };
        let bare = Descriptor::Bare(ms.clone());

        bare.satisfy(&mut txin, &satisfier, 0, 0).expect("satisfaction");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&sigser[..])
                    .into_script(),
                sequence: 100,
                witness: vec![],
            }
        );
        assert_eq!(bare.unsigned_script_sig(), bitcoin::Script::new());

        let pkh: Descriptor<_, DummyKeyHash> = Descriptor::Pkh(pk);
        pkh.satisfy(&mut txin, &satisfier, 0, 0).expect("satisfaction");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&sigser[..])
                    .push_key(&pk)
                    .into_script(),
                sequence: 100,
                witness: vec![],
            }
        );
        assert_eq!(pkh.unsigned_script_sig(), bitcoin::Script::new());

        let wpkh: Descriptor<_, DummyKeyHash> = Descriptor::Wpkh(pk);
        wpkh.satisfy(&mut txin, &satisfier, 0, 0).expect("satisfaction");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: bitcoin::Script::new(),
                sequence: 100,
                witness: vec![
                    sigser.clone(),
                    pk.to_bytes(),
                ],
            }
        );
        assert_eq!(wpkh.unsigned_script_sig(), bitcoin::Script::new());

        let shwpkh: Descriptor<_, DummyKeyHash> = Descriptor::ShWpkh(pk);
        shwpkh.satisfy(&mut txin, &satisfier, 0, 0).expect("satisfaction");
        let redeem_script = script::Builder::new()
            .push_opcode(opcodes::all::OP_PUSHBYTES_0)
            .push_slice(&hash160::Hash::from_hex(
                "d1b2a1faf62e73460af885c687dee3b7189cd8ab",
            ).unwrap()[..])
            .into_script();
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&redeem_script[..])
                    .into_script(),
                sequence: 100,
                witness: vec![
                    sigser.clone(),
                    pk.to_bytes(),
                ],
            }
        );
        assert_eq!(
            shwpkh.unsigned_script_sig(),
            script::Builder::new()
                .push_slice(&redeem_script[..])
                .into_script()
        );

        let sh = Descriptor::Sh(ms.clone());
        sh.satisfy(&mut txin, &satisfier, 0, 0).expect("satisfaction");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&sigser[..])
                    .push_slice(&ms.encode()[..])
                    .into_script(),
                sequence: 100,
                witness: vec![],
            }
        );
        assert_eq!(sh.unsigned_script_sig(), bitcoin::Script::new());

        let wsh = Descriptor::Wsh(ms.clone());
        wsh.satisfy(&mut txin, &satisfier, 0, 0).expect("satisfaction");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: bitcoin::Script::new(),
                sequence: 100,
                witness: vec![
                    sigser.clone(),
                    ms.encode().into_bytes(),
                ],
            }
        );
        assert_eq!(wsh.unsigned_script_sig(), bitcoin::Script::new());

        let shwsh = Descriptor::ShWsh(ms.clone());
        shwsh.satisfy(&mut txin, &satisfier, 0, 0).expect("satisfaction");
        assert_eq!(
            txin,
            bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: script::Builder::new()
                    .push_slice(&ms.encode().to_v0_p2wsh()[..])
                    .into_script(),
                sequence: 100,
                witness: vec![
                    sigser.clone(),
                    ms.encode().into_bytes(),
                ],
            }
        );
        assert_eq!(
            shwsh.unsigned_script_sig(),
            script::Builder::new()
                .push_slice(&ms.encode().to_v0_p2wsh()[..])
                .into_script()
        );
    }
}
