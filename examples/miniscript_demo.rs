//! Example: Compiler output.

extern crate bitcoin;
extern crate miniscript;
extern crate secp256k1;

use miniscript::policy::concrete::Policy;
use miniscript::policy::Liftable;
use miniscript::policy::{compiler, Concrete};
use miniscript::{Descriptor, Miniscript, MiniscriptKey};
use secp256k1::{Secp256k1, VerifyOnly};
use std::collections::HashMap;
use std::str::FromStr;

fn thresh_str(k: usize, n: usize) -> Policy<String> {
    let mut ms = String::new();
    ms.push_str(&format!("thresh({}", k));
    for i in 0..n {
        ms.push_str(&format!(",pk(F{})", i));
    }
    ms.push_str(")");
    Policy::<String>::from_str(&ms).unwrap()
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

// Basic example
fn demo1() {}

fn main() {
    let (pks, der_sigs, secp_sigs, sighash, secp) = setup_keys_sigs(53);

    //Without any probabilities.

    let good_case = thresh_str(35, 50);

    let emergency_path =
        Policy::<String>::from_str("and(thresh(2,pk(E0),pk(E1),pk(E2)),after(4032))").unwrap();

    // We can easily compose policies.
    let liquid_policy =
        Policy::<String>::from_str(&format!("or({},{})", good_case, emergency_path)).unwrap();

    let liquid_ms = liquid_policy.compile().unwrap();
    let liq_des = Descriptor::Wsh(liquid_ms);

    println!("{}", liq_des);
    // We can also assign probabilities.
    let liquid_policy =
        Policy::<String>::from_str(&format!("or(999@{},1@{})", good_case, emergency_path)).unwrap();

    let liquid_ms = liquid_policy.compile().unwrap();
    let liq_des = Descriptor::Wsh(liquid_ms);
    println!("{}", liq_des);

    //    let mut transfn = |x: &String| -> Result<bitcoin::PublicKey, String> {
    //        Ok(pks[0])
    //    };

    //    let des = Descriptor::<bitcoin::PublicKey>::from_str(&format!("wsh(pk({}))", pks[0])).unwrap();
    //
    //    let res  = des.translate_pk(|x| -> Result<bitcoin::PublicKey, String> {
    //        Ok(pks[1])
    //    }, |x| -> Result<bitcoin_hashes::hash160::Hash, String> {
    //        Ok(pks[1].to_pubkeyhash())
    //    });

    //    let mut transfn = |x: &String| -> Result<bitcoin::PublicKey, String> {
    //        match x.as_ref(){
    //            "E0" => Ok(pks[0]),
    //            "E1" => Ok(pks[1]),
    //            "E2" => Ok(pks[2]),
    //            _ => Err("0".to_owned()),
    //        }
    //    };
    //
    //
    //    println!("{}", ms);
    //    println!("{}", good_case.compile().unwrap());
    //    println!("{}", emergency_path.compile().unwrap());
    //
    //
    //    let res  = emergency_path.translate_pk(|x| -> Result<bitcoin::PublicKey, String> {
    //            Ok(pks[1])
    //        });
    //    println!("{}", liquid_ms);
    //
    //    //Then we can do some Semantic analysis
    //    let mut semantic = liquid_policy.lift();
    //    println!("The total number of keys: {}", semantic.n_keys());
    //    let liquid_policy_before_age = semantic.clone().at_age(4031);
    //    let liquid_policy_after_age = semantic.clone().at_age(4033);
    //
    //    println!("Keys at age: 4031 {}", liquid_policy_before_age.n_keys());
    //    println!("Keys at age: 4033 {}", liquid_policy_after_age.n_keys());

    //
}
