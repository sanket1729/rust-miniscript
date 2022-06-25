// BIP322 Generic Signature Algorithm
// Written in 2021 by
//     Rajarshi Maitra <rajarshi149@protonmail.com>]
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

//! # BIP322 Generic Signed Message Structure
//!
//! This module implements the BIP322 Generic Message Signer and Validator
//!
//! `https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki`
//!

use std::collections::HashMap;
use std::convert::From;

use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::{
    borrow_slice_impl, hash_newtype, hex_fmt_impl, index_impl, serde_impl, sha256,
    sha256t_hash_newtype, Hash,
};
use bitcoin::psbt::PartiallySignedTransaction;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{EcdsaSighashType, OutPoint, PublicKey, Transaction, TxIn, TxOut};

use super::interpreter::{Error as InterpreterError, Interpreter};
use super::{hash256, Descriptor};

// BIP322 message tagged hash midstate
const MIDSTATE: [u8; 32] = [
    137, 110, 101, 166, 158, 24, 33, 51, 154, 160, 217, 89, 167, 185, 222, 252, 115, 60, 186, 140,
    151, 47, 2, 20, 94, 72, 184, 111, 248, 59, 249, 156,
];

// BIP322 Tagged Hash
sha256t_hash_newtype!(
    MessageHash,
    MessageTag,
    MIDSTATE,
    64,
    doc = "BIP322 message tagged hash",
    true
);

/// BIP322 Error types
#[derive(Debug)]
pub enum BIP322Error {
    /// BIP322 Internal Error
    InternalError(String),

    /// Signature Validation Error
    ValidationError(InterpreterError),
}

#[doc(hidden)]
impl From<InterpreterError> for BIP322Error {
    fn from(e: InterpreterError) -> BIP322Error {
        BIP322Error::ValidationError(e)
    }
}

/// Bip322 Signatures
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Bip322Signature {
    /// Legacy style. Only applicable for P2PKH message_challenge
    Legacy(Signature, PublicKey),

    /// Simple witness structure
    Simple(Vec<Vec<u8>>),

    /// Full `to_sign` transaction structure
    Full(Transaction),
}

/// TODO: Bip322 Signer structure
/// Update a Psbt with signatures required for signatures.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Bip322SignerSecrets {
    // Descriptor with secret keys
    desc: Descriptor<String>, // parse with secrets
    // Preimages
    sha256_preimages: HashMap<sha256::Hash, [u8; 32]>, // Similar maps for other hashes
}

/// Bip322 Signer that supports single and multiple Utxos
pub struct Bip322Signer {
    /// Age
    pub age: u32,
    /// Height
    pub height: u32,
    /// Script pubkey -> Secrets
    pub spk_secrets_map: HashMap<bitcoin::Script, Bip322SignerSecrets>,
}

impl Bip322Signer {
    /// Creates a signer for proving ownership of single funds
    pub fn addr() -> Self {
        todo!()
    }

    /// Creates a signer ...
    pub fn new_proof_of_funds() -> Self {
        todo!()
    }

    /// Look and infer the miniscript from txout/witness_script.
    ///
    /// # Returns:
    ///
    /// 1) Completed(Bip322Signature)
    /// 2) Insufficient information to finalize. Pass onto the next signer
    pub fn sign(&self, _psbt: &mut PartiallySignedTransaction, _msg: String) -> Result<(), ()> {
        todo!("Sanity checks that the descriptor correctly derives the address");
        // If the descriptor is BIP32 secret key, then we need to find the index corresponding to the wildcard
        // Substitute the index and get the concrete descriptor

        // Iterating over secrets (PublicKey -> SecretKey)
        // PsbtExt::sighash_msg => (Ecdsa(sighash::Message), Schnorr(sighash::Message))
        // 1) Ecdsa secp.sign_ecdsa
        // 2) Schnorr: Check if we know the internal key. sign_key_spend
        // 3) Schnorr script spend: sign_script_spend

        // Try finalize if possible
    }

    /// Better name
    pub fn finalize(&self, _psbt: &mut PartiallySignedTransaction) -> Result<Bip322Signature, ()> {
        todo!();
        // sign(sk, msg) -> sig
        // verify(pk, msg, sig) -> 0/1
    }
}

impl Bip322Signer {}

/// BIP322 validator structure
/// A standard for interoperable signed messages based on the Bitcoin Script format,
/// either for proving fund availability, or committing to a message as the intended
/// recipient of funds sent to the invoice address.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Bip322Validator {
    /// Message to be signed
    message: String,

    /// Signature to verify the message
    signature: Bip322Signature,

    /// script_pubkey to define the challenge script inside to_spend transaction
    /// here we take in descriptors to derive the resulting script_pubkey
    script_pubkey: bitcoin::Script,

    /// Age
    age: u32,

    /// Height
    height: u32,
}

impl Bip322Validator {
    /// Create a new BIP322 validator
    pub fn new(
        msg: String,
        sig: Bip322Signature,
        addr: bitcoin::Script,
        age: u32,
        height: u32,
    ) -> Self {
        Bip322Validator {
            message: msg,
            signature: sig,
            script_pubkey: addr,
            age,
            height,
        }
    }

    /// create the to_spend transaction
    pub fn to_spend(&self) -> Transaction {
        // create default input and output
        let mut vin = TxIn::default();
        let mut vout = TxOut::default();

        // calculate the message tagged hash
        let msg_hash = MessageHash::hash(&self.message.as_bytes()).into_inner();

        // mutate the input with appropriate script_sig and sequence
        vin.script_sig = Builder::new()
            .push_int(0)
            .push_slice(&msg_hash[..])
            .into_script();
        vin.sequence = 0;

        // mutate the value and script_pubkey as appropriate
        vout.value = 0;
        vout.script_pubkey = self.script_pubkey.clone();

        // create and return final transaction
        Transaction {
            version: 0,
            lock_time: 0,
            input: vec![vin],
            output: vec![vout],
        }
    }

    /// Create to_sign transaction
    /// This will create a transaction structure with empty signature and witness field
    /// its up to the user of the library to fill the Tx with appropriate signature and witness
    pub fn empty_to_sign(&self) -> Transaction {
        // create the appropriate input
        let outpoint = OutPoint::new(self.to_spend().txid(), 0);
        let mut input = TxIn::default();
        input.previous_output = outpoint;
        input.sequence = self.height;

        // create the output
        let output = TxOut {
            value: 0,
            script_pubkey: Builder::new()
                .push_opcode(opcodes::all::OP_RETURN)
                .into_script(),
        };

        // return resulting transaction
        Transaction {
            version: 2,
            lock_time: self.age,
            input: vec![input],
            output: vec![output],
        }
    }

    /// Validate a BIP322 Signature against the message and challenge script
    /// This will require a BIP322Signature inside the structure
    pub fn validate(&self) -> Result<bool, BIP322Error> {
        match &self.signature {
            // A Full signature can be validated directly against the `to_sign` transaction
            Bip322Signature::Full(to_sign) => self.tx_validation(to_sign),

            // If Simple Signature is provided, the resulting `to_sign` Tx will be computed
            Bip322Signature::Simple(witness) => {
                if !self.script_pubkey.is_witness_program() {
                    return Err(BIP322Error::InternalError("Simple style signature is only applicable for Segwit type message_challenge".to_string()));
                } else {
                    // create empty to_sign transaction
                    let mut to_sign = self.empty_to_sign();

                    to_sign.input[0].witness = bitcoin::Witness::from_vec(witness.to_owned());

                    self.tx_validation(&to_sign)
                }
            }

            // Legacy Signature can only be used to validate against P2PKH message_challenge
            Bip322Signature::Legacy(sig, pubkey) => {
                if !self.script_pubkey.is_p2pkh() {
                    return Err(BIP322Error::InternalError(
                        "Legacy style signature is only applicable for P2PKH message_challenge"
                            .to_string(),
                    ));
                } else {
                    let mut sig_ser = sig.serialize_der()[..].to_vec();

                    // By default SigHashType is ALL
                    sig_ser.push(EcdsaSighashType::All as u8);

                    let script_sig = Builder::new()
                        .push_slice(&sig_ser[..])
                        .push_key(&pubkey)
                        .into_script();

                    let mut to_sign = self.empty_to_sign(); // `to_sign` single-handedly produces both the scripts hmm..., interesting

                    to_sign.input[0].script_sig = script_sig;

                    self.tx_validation(&to_sign)
                }
            }
        }
    }

    // Internal helper function to perform transaction validation
    fn tx_validation(&self, to_sign: &Transaction) -> Result<bool, BIP322Error> {
        let _secp = Secp256k1::new();

        // create an Interpreter to validate to_spend transaction
        let interpreter = Interpreter::from_txdata(
            &self.script_pubkey,
            &to_sign.input[0].script_sig,
            &to_sign.input[0].witness,
            0,
            0,
        )?;

        // create the signature verification function
        // let vfyfn = interpreter.verify_ecdsa(&secp, &to_sign, 0, 0);

        let mut result = false;

        for elem in interpreter.iter_assume_sigs() {
            match elem {
                Ok(_) => result = true,
                Err(e) => return Err(BIP322Error::ValidationError(e)),
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod test {
    use bitcoin::hashes::sha256t::Tag;
    use bitcoin::hashes::{sha256, HashEngine};
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::{EcdsaSighashType, PrivateKey};

    use super::*;

    #[test]
    fn test_bip322_validation() {
        // Create key pairs and secp context
        let sk =
            PrivateKey::from_wif("cVt4o7BGAig1UXywgGSmARhxMdzP5qvQsxKkSsc1XEkw3tDTQFpy").unwrap();

        let ctx = Secp256k1::new();
        let pk = sk.public_key(&ctx);

        // wpkh descriptor from pubkey
        let desc = Descriptor::new_wpkh(pk).unwrap();

        // Corresponding p2pkh script. used for sighash calculation
        let p2pkh_script = bitcoin::Script::new_p2pkh(&pk.pubkey_hash());

        let message = "Hello World".to_string();
        let age = 0;
        let height = 0;

        // Create to_spend transaction
        let to_spend = {
            // create default input and output
            let mut vin = TxIn::default();
            let mut vout = TxOut::default();

            // calculate the message tagged hash
            let msg_hash = MessageHash::hash(message.as_bytes()).into_inner();

            // mutate the input with appropriate script_sig and sequence
            vin.script_sig = Builder::new()
                .push_int(0)
                .push_slice(&msg_hash[..])
                .into_script();
            vin.sequence = 0;

            // mutate the value and script_pubkey as appropriate
            vout.value = 0;
            vout.script_pubkey = desc.script_pubkey();

            // create and return final transaction
            Transaction {
                version: 0,
                lock_time: 0,
                input: vec![vin],
                output: vec![vout],
            }
        };

        // create an empty to_sign transaction
        let mut empty_to_sign = {
            // create the appropriate input
            let outpoint = OutPoint::new(to_spend.txid(), 0);
            let mut input = TxIn::default();
            input.previous_output = outpoint;
            input.sequence = height;

            // create the output
            let output = TxOut {
                value: 0,
                script_pubkey: Builder::new()
                    .push_opcode(opcodes::all::OP_RETURN)
                    .into_script(),
            };

            // return resulting transaction
            Transaction {
                version: 2,
                lock_time: age,
                input: vec![input],
                output: vec![output],
            }
        };

        // --------------------------------------------------------------
        // Check BIP322Signature::FUll

        // Generate witness for above wpkh pubkey
        let mut sighash_cache = bitcoin::util::sighash::SighashCache::new(&empty_to_sign);
        let message =
            sighash_cache.segwit_signature_hash(0, &p2pkh_script, 0, EcdsaSighashType::All);
        let message = Message::from_slice(&message.unwrap()).unwrap();

        let signature = ctx.sign_ecdsa(&message, &sk.inner);
        let der = signature.serialize_der();
        let mut sig_with_hash = der[..].to_vec();
        sig_with_hash.push(EcdsaSighashType::All as u8);

        let witness: Vec<Vec<u8>> = vec![sig_with_hash, pk.to_bytes()];
        empty_to_sign.input[0].witness = bitcoin::Witness::from_vec(witness.clone());

        let bip322_signature = Bip322Signature::Full(empty_to_sign);

        // Create BIP322 Validator
        let bip322_1 = Bip322Validator {
            message: "Hello World".to_string(),
            script_pubkey: desc.script_pubkey(),
            signature: bip322_signature,
            age: 0,
            height: 0,
        };
        let mut bip322_2 = bip322_1.clone();
        let mut bip322_3 = bip322_1.clone();

        // Check validation
        assert_eq!(bip322_1.validate().unwrap(), true);

        // ------------------------------------------------------------
        // Check Bip322Signature::Simple

        // Same structure can be validated with Simple type signature
        bip322_2.signature = Bip322Signature::Simple(witness);

        assert_eq!(bip322_2.validate().unwrap(), true);

        // ------------------------------------------------------------
        // Check Bip322Signature::Legacy

        let desc = Descriptor::new_pkh(pk);

        // Replace previous message_challenge with p2pkh
        bip322_3.script_pubkey = desc.script_pubkey();

        // Create empty to_sign
        let to_sign = bip322_3.empty_to_sign();

        // Compute SigHash and Signature
        let message =
            to_sign.signature_hash(0, &desc.script_pubkey(), EcdsaSighashType::All as u32);
        let message = Message::from_slice(&message[..]).unwrap();
        let signature = ctx.sign_ecdsa(&message, &sk.inner);

        // Create Bip322Signature::Legacy
        let bip322_sig = Bip322Signature::Legacy(signature, pk);
        bip322_3.signature = bip322_sig;

        // Check validation
        assert_eq!(bip322_3.validate().unwrap(), true);
    }

    #[test]
    fn test_tagged_hash() {
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash("BIP0322-signed-message".as_bytes());
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);

        assert_eq!(engine.midstate().into_inner(), MIDSTATE);
        assert_eq!(engine.midstate(), MessageTag::engine().midstate());
    }
}
