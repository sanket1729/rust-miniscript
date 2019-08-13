extern crate bitcoin;
extern crate miniscript;
extern crate secp256k1;

use miniscript::SatisfiedConstraints::{SatisfiedConstraint, Stack, Error};
use miniscript::policy::concrete::Policy;
use miniscript::{Descriptor, Miniscript, MiniscriptKey};
use secp256k1::{Secp256k1, VerifyOnly};
use std::collections::HashMap;
use std::str::FromStr;
use bitcoin::PublicKey;
use miniscript::SatisfiedConstraints;
use miniscript::BitcoinSig;
use miniscript::SatisfiedConstraints::StackElement;

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

fn from_stack<'stack, 'elem, F>(
    verify_fn: F,
    stack: Stack<'stack>,
    ms: &'elem Miniscript<bitcoin::PublicKey>,
) -> SatisfiedConstraints<'elem, 'stack, F>
    where
        F: FnMut(&bitcoin::PublicKey, BitcoinSig) -> bool,
{
    SatisfiedConstraints {
        verify_sig: verify_fn,
        stack: stack,
        public_key: None,
        state: vec![NodeEvaluationState {
            node: ms,
            n_evaluated: 0,
            n_satisfied: 0,
        }],
        age: 1002,
        height: 1002,
        has_errored: false,
    }
};

fn main(){
    let (pks, der_sigs, secp_sigs, _sighash, _secp) = setup_keys_sigs(53);
    let vfyfn =
        |pk: &bitcoin::PublicKey, (sig, _)| secp.verify(&sighash, &sig, &pk.key).is_ok();

    //Check Thres
    let stack = Stack(vec![
        StackElement::Push(&der_sigs[0]),
        StackElement::Push(&der_sigs[1]),
        StackElement::Push(&der_sigs[2]),
        StackElement::Dissatisfied,
        StackElement::Dissatisfied,
    ]);
    let elem = Miniscript::<PublicKey>::from_str(&fromat!(
            "thresh(3,c:pk({}),sc:pk({}),sc:pk({}),sc:pk({}),sc:pk({}))",
            pks[4],
            pks[3],
            pks[2],
            pks[1],
            pks[0],
        )).unwrap();
    let constraints = from_stack(&vfyfn, stack, &elem);

    let thresh_satisfied: Result<Vec<SatisfiedConstraint>, Error> = constraints.collect();
    assert_eq!(
        thresh_satisfied.unwrap(),
        vec![
            SatisfiedConstraint::PublicKey {
                key: &pks[2],
                sig: secp_sigs[2].clone(),
            },
            SatisfiedConstraint::PublicKey {
                key: &pks[1],
                sig: secp_sigs[1].clone(),
            },
            SatisfiedConstraint::PublicKey {
                key: &pks[0],
                sig: secp_sigs[0].clone(),
            }
        ]
    );
}