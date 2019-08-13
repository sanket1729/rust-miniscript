//! Example: Compiler output.

extern crate bitcoin;
extern crate miniscript;
extern crate secp256k1;

use miniscript::policy::concrete::Policy;
use miniscript::{Descriptor, Miniscript, MiniscriptKey};
use secp256k1::{Secp256k1, VerifyOnly};
use std::collections::HashMap;
use std::str::FromStr;
use bitcoin::PublicKey;

fn setup_keys_sigs(
    n: usize,
) -> (
    Vec<bitcoin::PublicKey>,
    Vec<Vec<u8>>,
    Vec<secp256k1::Signature>,
    secp256k1::Message,
    Secp256k1<VerifyOnly>,
) {
    let secp_sign = secp256k1::Secp256k1::signing_only();
    let secp_verify = secp256k1::Secp256k1::verification_only();
    let msg =
        secp256k1::Message::from_slice(&b"Yoda: btc, I trust. HODL I must!"[..]).expect("32 bytes");
    let mut pks = vec![];
    let mut secp_sigs = vec![];
    let mut der_sigs = vec![];
    let mut sk = [0; 32];
    for i in 1..n + 1 {
        sk[0] = i as u8;
        sk[1] = (i >> 8) as u8;
        sk[2] = (i >> 16) as u8;

        let sk = secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key");
        let pk = bitcoin::PublicKey {
            key: secp256k1::PublicKey::from_secret_key(&secp_sign, &sk),
            compressed: true,
        };
        let sig = secp_sign.sign(&msg, &sk);
        secp_sigs.push(sig);
        let mut sigser = sig.serialize_der();
        sigser.push(0x01); // sighash_all
        pks.push(pk);
        der_sigs.push(sigser);
    }
    (pks, der_sigs, secp_sigs, msg, secp_verify)
}

fn thresh_pk(k: usize, n: usize, pks: Vec<bitcoin::PublicKey>) -> Policy<PublicKey> {
    let mut ms = String::new();
    ms.push_str(&format!("thresh({}", k));
    for i in 0..n {
        ms.push_str(&format!(",pk({})", pks[i]));
    }
    ms.push_str(")");
    Policy::<bitcoin::PublicKey>::from_str(&ms).unwrap()
}

fn main() {
    let (pks, _der_sigs, secp_sigs, _sighash, _secp) = setup_keys_sigs(53);
    let mut sigs = HashMap::<bitcoin::PublicKey, miniscript::BitcoinSig>::new();
    let mut emer_sigs = HashMap::<bitcoin::PublicKey, miniscript::BitcoinSig>::new();
    let mut emer_sigs_pk = HashMap::<bitcoin_hashes::hash160::Hash, bitcoin::PublicKey>::new();


    for i in 0..35{
        sigs.insert(pks[i], (secp_sigs[i], bitcoin::SigHashType::All));
    }

    for i in 50..52{
        emer_sigs.insert(pks[i], (secp_sigs[i], bitcoin::SigHashType::All));
        emer_sigs_pk.insert(pks[i].to_pubkeyhash(), pks[i].clone());
    }

    let mut tx = bitcoin::Transaction {
        version: 2,
        lock_time: 0,
        input: vec![bitcoin::TxIn {
            previous_output: Default::default(),
            script_sig: bitcoin::Script::new(),
            sequence: 0xffffffff,
            witness: vec![],
        }],
        output: vec![bitcoin::TxOut {
            script_pubkey: bitcoin::Script::new(),
            value: 100_000_000,
        }],
    };

    let good_path = thresh_pk(35, 50, pks.clone());
    let emergency_path = thresh_pk(2,3, vec![pks[50].clone(), pks[51].clone(), pks[52].clone()]);
    let liquid_policy = Policy::<PublicKey>::from_str(&format!("or(999@{},1@and({},after(4032)))", good_path, emergency_path)).unwrap();

//    println!("{}", liquid_policy);
    let ms = liquid_policy.compile().unwrap();
    let des = Descriptor::Wsh(ms);


    let ms: Miniscript<bitcoin::PublicKey> = Miniscript::from_str(&format!(
            "or_d(thresh_m(3,{},{},{},{},{}),\
             and_v(v:thresh(2,c:pk_h({}),\
             ac:pk_h({}),ac:pk_h({})),after(10000)))",
            pks[0],
            pks[1],
            pks[2],
            pks[3],
            pks[4],
            pks[5].to_pubkeyhash(),
            pks[6].to_pubkeyhash(),
            pks[7].to_pubkeyhash()
        )).unwrap();


    let bitcoinsig = (secp_sigs[0], bitcoin::SigHashType::All);
    let mut sigvec = secp_sigs[0].serialize_der();
    sigvec.push(1); // sighash all

    let no_sat = HashMap::<bitcoin::PublicKey, miniscript::BitcoinSig>::new();
    let mut left_sat = HashMap::<bitcoin::PublicKey, miniscript::BitcoinSig>::new();
    let mut right_sat =
        HashMap::<bitcoin_hashes::hash160::Hash, (bitcoin::PublicKey, miniscript::BitcoinSig)>::new();

    for i in 0..5 {
        left_sat.insert(pks[i].clone(), bitcoinsig);
    }
    for i in 5..8 {
        right_sat.insert(pks[i].clone().to_pubkeyhash(), (pks[i].clone(), bitcoinsig));
    }

    println!("{:?}", ms.satisfy(&left_sat, 0, 0));

    println!("{:?}", ms.satisfy( &right_sat, 10000, 0));
}