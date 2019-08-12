//! Example: Compiler output.

extern crate bitcoin;
extern crate miniscript;
extern crate secp256k1;

use bitcoin::PublicKey;
use miniscript::policy::concrete::Policy;
use miniscript::policy::Liftable;
use miniscript::policy::{compiler, Concrete};
use miniscript::{Descriptor, Miniscript, MiniscriptKey};
use secp256k1::{Secp256k1, VerifyOnly};
use std::collections::HashMap;
use std::str::FromStr;

fn thresh_str(k: usize, n: usize, pks: Vec<bitcoin::PublicKey>) -> Policy<PublicKey> {
    let mut ms = String::new();
    ms.push_str(&format!("thresh({}", k));
    for i in 0..n {
        ms.push_str(&format!(",pk({})", pks[i]));
    }
    ms.push_str(")");
    Policy::<bitcoin::PublicKey>::from_str(&ms).unwrap()
}

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

fn main() {
    let (pks, der_sigs, secp_sigs, sighash, secp) = setup_keys_sigs(53);

    //Without any probabilities.

    let good_case = thresh_str(35, 50, pks.clone());

    let emergency_path = Policy::<PublicKey>::from_str(&format!(
        "and(thresh(2,pk({}),pk({}),pk({})),after(4032))",
        pks[50], pks[51], pks[52]
    ))
    .unwrap();

    // We can easily compose policies.
    let liquid_policy =
        Policy::<PublicKey>::from_str(&format!("or({},{})", good_case, emergency_path)).unwrap();

    let liquid_ms = liquid_policy.compile().unwrap();
    let liq_des = Descriptor::Wsh(liquid_ms);

    println!("Without probabilities");
    println!(" Max satisfaction weight: {} \
    Witness Script len{}", liq_des.max_satisfaction_weight(), liq_des.witness_script().len());
    // We can also assign probabilities.
    let liquid_policy =
        Policy::<PublicKey>::from_str(&format!("or(999@{},1@{})", good_case, emergency_path))
            .unwrap();

    let liquid_ms = liquid_policy.compile().unwrap();
    let liq_des = Descriptor::Wsh(liquid_ms);
    println!("With probability odds: 999:1");
    println!(" Max satisfaction weight: {} \
    Witness Script len{}", liq_des.max_satisfaction_weight(), liq_des.witness_script().len());
}
