use std::collections::BTreeMap;
use std::convert::TryInto;
use std::ops::Add;
use std::str::FromStr;
use std::vec;

use bincode::config::LittleEndian;
use bitcoin::bech32::FromBase32;
use bitcoin::blockdata::opcodes::all;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::{hex, sha256, Hash};
use bitcoin::psbt::serialize::Deserialize;
use bitcoin::psbt::{Input, Output, PartiallySignedTransaction, TapTree};
use bitcoin::schnorr::{TapTweak, TweakedKeyPair, TweakedPublicKey, UntweakedKeyPair};
use bitcoin::secp256k1::{Message, Parity, Secp256k1, SecretKey, Signature};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::util::sighash::{Prevouts, ScriptPath, SighashCache};
use bitcoin::util::taproot::LeafVersion::TapScript;
use bitcoin::util::taproot::{
    ControlBlock, LeafVersion, NodeInfo, TapBranchHash, TapBranchTag, TapLeafHash, TapSighashHash,
    TaprootBuilder, TaprootMerkleBranch, TaprootSpendInfo,
};
use bitcoin::{
    Address, AddressType, KeyPair, Network, OutPoint, PrivateKey, SchnorrSig, SchnorrSighashType,
    Script, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
};
use electrum_client::{Client, ElectrumApi};
use miniscript::psbt::{PsbtExt, PsbtInputSatisfier};
use miniscript::{
    DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, Miniscript, Tap, ToPublicKey,
};

fn main() {
    let secp = Secp256k1::new();
    let alice_secret =
        SecretKey::from_str("2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90")
            .unwrap();
    let bob_secret =
        SecretKey::from_str("81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9")
            .unwrap();
    let internal_secret =
        SecretKey::from_str("1229101a0fcf2104e8808dab35661134aa5903867d44deb73ce1c7e4eb925be8")
            .unwrap();

    let alice = KeyPair::from_secret_key(&secp, alice_secret);
    let bob = KeyPair::from_secret_key(&secp, bob_secret);
    let internal = KeyPair::from_secret_key(&secp, internal_secret);
    let preimage =
        Vec::from_hex("107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f").unwrap();

    let preimage_hash = bitcoin::hashes::sha256::Hash::hash(&preimage);

    println!("alice public key {}", alice.public_key());
    println!("bob public key {}", bob.public_key());
    println!("internal public key {}", internal.public_key());

    println!("preimage {}", preimage_hash.to_string());

    let alice_ms = Miniscript::<DefiniteDescriptorKey, Tap>::from_str(&format!(
        "and_v(v:pk({}),older(144))",
        bob.public_key()
    ))
    .unwrap();

    let bob_ms = Miniscript::<DefiniteDescriptorKey, Tap>::from_str(&format!(
        "and_v(v:sha256({}),pk({}))",
        preimage_hash,
        alice.public_key()
    ))
    .unwrap();

    let desc = Descriptor::<DefiniteDescriptorKey>::from_str(&format!(
        "tr({},{{{},{}}})",
        internal.public_key(),
        &alice_ms,
        &bob_ms
    ))
    .unwrap();

    // let tap_tree = TapTree::from_builder(builder).unwrap();

    // let tap_info = tap_tree
    //     .into_builder()
    //     .finalize(&secp, internal.public_key())
    //     .unwrap();

    // let merkle_root = tap_info.merkle_root();
    // let tweak_key_pair = internal.tap_tweak(&secp, merkle_root).into_inner();

    // let address = Address::p2tr(
    //     &secp,
    //     tap_info.internal_key(),
    //     tap_info.merkle_root(),
    //     bitcoin::Network::Testnet,
    // );

    let address = desc.address(bitcoin::Network::Testnet).unwrap();

    let client = Client::new("ssl://electrum.blockstream.info:60002").unwrap();
    let vec_tx_in = client
        .script_list_unspent(&address.script_pubkey())
        .unwrap()
        .iter()
        .map(|l| {
            return TxIn {
                previous_output: OutPoint::new(l.tx_hash, l.tx_pos.try_into().unwrap()),
                script_sig: Script::new(),
                sequence: 0xFFFFFFFF,
                witness: Witness::default(),
            };
        })
        .collect::<Vec<TxIn>>();

    let prev_tx = vec_tx_in
        .iter()
        .map(|tx_id| client.transaction_get(&tx_id.previous_output.txid).unwrap())
        .collect::<Vec<Transaction>>();

    let tx = Transaction {
        version: 2,
        lock_time: 0,
        input: vec![TxIn {
            previous_output: vec_tx_in[0].previous_output.clone(),
            script_sig: Script::new(),
            sequence: 0xFFFFFFFF,
            witness: Witness::default(),
        }],

        output: vec![TxOut {
            value: 700,
            script_pubkey: Address::from_str(
                "tb1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gskndd0z",
            )
            .unwrap()
            .script_pubkey(),
        }],
    };

    // Creator role of psbt
    let mut psbt = PartiallySignedTransaction::from_unsigned_tx(tx.clone()).unwrap();

    // Update all the descriptor information. Updater role of Psbt
    psbt.update_input_with_descriptor(0, &desc).unwrap();
    // descriptors don't have preimages so feed them manually
    psbt.inputs[0]
        .sha256_preimages
        .insert(preimage_hash, preimage.to_vec());

    let prevouts = Prevouts::One(0, prev_tx[0].output[0].clone());

    let sighash_sig = SighashCache::new(&mut tx.clone())
        .taproot_script_spend_signature_hash(
            0,
            &prevouts,
            ScriptPath::with_defaults(&bob_ms.encode()),
            SchnorrSighashType::AllPlusAnyoneCanPay,
        )
        .unwrap();

    let key_sig = SighashCache::new(&mut tx.clone())
        .taproot_key_spend_signature_hash(0, &prevouts, SchnorrSighashType::AllPlusAnyoneCanPay)
        .unwrap();

    println!("key signing sighash {} ", key_sig);

    println!("script sighash {} ", sighash_sig);

    let sig = secp.sign_schnorr(&Message::from_slice(&sighash_sig).unwrap(), &bob);

    // let actual_control = tap_info
    //     .control_block(&(bob_script.clone(), LeafVersion::TapScript))
    //     .unwrap();

    // let res =
    //     actual_control.verify_taproot_commitment(&secp, tweak_key_pair.public_key(), &bob_script);

    // println!("is taproot committed? {} ", res);

    // println!("control block {} ", actual_control.serialize().to_hex());

    // let mut b_tree_map = BTreeMap::<ControlBlock, (Script, LeafVersion)>::default();
    // b_tree_map.insert(
    //     actual_control.clone(),
    //     (bob_script.clone(), LeafVersion::TapScript),
    // );

    let schnorr_sig = SchnorrSig {
        sig,
        hash_ty: SchnorrSighashType::AllPlusAnyoneCanPay,
    };

    let bob_leaf_hash = ScriptPath::with_defaults(&bob_ms.encode()).leaf_hash();
    psbt.inputs[0]
        .tap_script_sigs
        .insert((bob.public_key(), bob_leaf_hash), schnorr_sig);

    // let wit = Witness::from_vec(vec![
    //     schnorr_sig.to_vec(),
    //     preimage.clone(),
    //     bob_script.to_bytes(),
    //     actual_control.serialize(),
    // ]);

    // tx.input[0].witness = wit;

    psbt.finalize_mut(&secp).unwrap();
    let tx = psbt.extract_tx();
    println!("Address: {} ", address.to_string());

    // this part fails fix me plz !!!
    let tx_id = client.transaction_broadcast(&tx).unwrap();
    println!("transaction hash: {}", tx_id.to_string());

    // sig
    println!("signature {:#?}", sig.to_hex());
    println!("Input preimage {}", preimage.to_hex());
    println!("script {}", bob_ms.encode().to_hex());
    // println!("control block {:#?}", actual_control.serialize().to_hex());
}
