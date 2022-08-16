use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::blockdata::opcodes::all;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::serialize::Deserialize;
use bitcoin::psbt::{Input, PartiallySignedTransaction, TapTree};
use bitcoin::schnorr::TapTweak;
use bitcoin::secp256k1::{Message, Parity, Secp256k1, SecretKey};
use bitcoin::util::sighash::{Prevouts, ScriptPath, SighashCache};
use bitcoin::util::taproot::LeafVersion::TapScript;
use bitcoin::util::taproot::{
    ControlBlock, LeafVersion, TapBranchHash, TapLeafHash, TaprootBuilder, TaprootMerkleBranch,
};
use bitcoin::{Address, KeyPair, SchnorrSig, SchnorrSighashType, Script, Transaction, Witness};
use miniscript::psbt::PsbtExt;

pub fn main() {
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

    let alice_script = Script::from_hex(
        "029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac",
    )
    .unwrap();

    let bob_script = Builder::new()
        .push_opcode(all::OP_SHA256)
        .push_slice(&preimage_hash)
        .push_opcode(all::OP_EQUALVERIFY)
        .push_x_only_key(&bob.public_key())
        .push_opcode(all::OP_CHECKSIG)
        .into_script();

    // let alice_leaf = TapLeafHash::from_script(&alice_script, TapScript);
    // let bob_leaf = TapLeafHash::from_script(&bob_script, TapScript);

    // let alice_branch = TapBranchHash::from_inner(alice_leaf.into_inner());
    // let bob_branch = TapBranchHash::from_inner(bob_leaf.into_inner());

    // let branch = TapBranchHash::from_node_hashes(
    //     sha256::Hash::from_inner(alice_branch.into_inner()),
    //     sha256::Hash::from_inner(bob_branch.into_inner()),
    // );

    let builder =
        TaprootBuilder::with_huffman_tree(vec![(1, bob_script.clone()), (1, alice_script.clone())])
            .unwrap();

    let tap_tree = TapTree::from_builder(builder).unwrap();

    let tap_info = tap_tree
        .into_builder()
        .finalize(&secp, internal.public_key())
        .unwrap();

    let merkle_root = tap_info.merkle_root();
    let tweak_key_pair = internal.tap_tweak(&secp, merkle_root).into_inner();

    let address = Address::p2tr(
        &secp,
        tap_info.internal_key(),
        tap_info.merkle_root(),
        bitcoin::Network::Regtest,
    );

    println!("tweaked address {} ", address.to_string());
    let tx = unsigned_tx();

    let sighash_sig = SighashCache::new(&mut tx.clone())
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&vec![tx_input().output[0].clone()]),
            ScriptPath::with_defaults(&bob_script),
            SchnorrSighashType::Default,
        )
        .unwrap();

    let prev_outs = vec![tx_input().output[0].clone()];
    let key_sig = SighashCache::new(&mut tx.clone())
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&prev_outs),
            SchnorrSighashType::Default,
        )
        .unwrap();

    println!("key signing sighash {} ", key_sig);

    println!("script sighash {} ", sighash_sig);

    // Note: Removed the tweaking from here. This is not needed and is wrong to do
    let sig = secp.sign_schnorr(&Message::from_slice(&sighash_sig).unwrap(), &bob);

    let actual_control = tap_info
        .control_block(&(bob_script.clone(), LeafVersion::TapScript))
        .unwrap();

    let res =
        actual_control.verify_taproot_commitment(&secp, tweak_key_pair.public_key(), &bob_script);

    println!("is taproot comitented? {} ", res);

    println!(" control block {} ", actual_control.serialize().to_hex());

    let mut input = Input::default();

    let mut b_tree_map = BTreeMap::<ControlBlock, (Script, LeafVersion)>::default();
    b_tree_map.insert(
        actual_control.clone(),
        (bob_script.clone(), LeafVersion::TapScript),
    );

    input.tap_scripts = b_tree_map;
    input.tap_internal_key = Some(tap_info.internal_key());

    input.witness_utxo = Some(tx_input().output[0].clone());
    input.tap_merkle_root = tap_info.merkle_root();

    let mut pst = PartiallySignedTransaction {
        unsigned_tx: unsigned_tx(),
        version: 2,
        xpub: BTreeMap::default(),
        proprietary: BTreeMap::default(),
        unknown: BTreeMap::default(),
        inputs: vec![input],
        outputs: vec![],
    };

    let schnorr_sig = SchnorrSig {
        sig,
        hash_ty: SchnorrSighashType::Default,
    };

    // this part fails
    let wit = Witness::from_vec(vec![
        schnorr_sig.to_vec(),
        preimage.clone(),
        bob_script.to_bytes(),
        actual_control.serialize(),
    ]);

    pst.inputs[0].final_script_witness = Some(wit);
    // pst.finalize(&secp).unwrap();

    // sig
    println!("signature {}", sig);
    println!("Input preimage {}", preimage.to_hex());
    println!("script {}", bob_script.to_hex());
    println!("control block {:#?}", actual_control.serialize().to_hex());
}

pub fn unsigned_tx() -> Transaction {
    return Transaction::deserialize(&Vec::from_hex("020000000171f2f89c07c3b58c7b0cf3654ba049d28bbcc76b7298f41c17e7b1a3149040ec0000000000ffffffff01905f010000000000160014ceb2d28afdcad1ae0fc2cf81cb929ba29e83468200000000").unwrap()).unwrap();
}

pub fn tx_input() -> Transaction {
    return Transaction::deserialize(&Vec::from_hex("020000000001010aa633878f200c80fc8ec88f13f746e5870be7373ad5d78d22e14a402d6c6fc20000000000feffffff02a086010000000000225120a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951c759f405000000001600147bf84e78c81b9fed7a47b9251d95b13d6ebac14102473044022017de23798d7a01946744421fbb79a48556da809a9ffdb729f6e5983051480991022052460a5082749422804ad2a25e6f8335d5cf31f69799cece4a1ccc0256d5010701210257e0052b0ec6736ee13392940b7932571ce91659f71e899210b8daaf6f17027500000000").unwrap()).unwrap();
}

pub fn signed_tx() -> Transaction {
    return Transaction::deserialize(&Vec::from_hex("0200000000010171f2f89c07c3b58c7b0cf3654ba049d28bbcc76b7298f41c17e7b1a3149040ec0000000000ffffffff01905f010000000000160014ceb2d28afdcad1ae0fc2cf81cb929ba29e834682044054d5ee309be92f531d62449d8ef82b216f1e5b6229aaef918a78c26ce6dd66d57c523202b4650302667723f63dd5a87b2370ada51e08de0eccb27a80450ff9bf20107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f45a8206c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd533388204edfcf9dfe6c0b5c83d1ab3f78d1b39a46ebac6798e08e19761f5ed89ec83c10ac41c1f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1cc81451874bd9ebd4b6fd4bba1f84cdfb533c532365d22a0a702205ff658b17c900000000").unwrap()).unwrap();
}
