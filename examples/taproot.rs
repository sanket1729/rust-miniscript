use std::str::FromStr;

use bitcoin::util::address::WitnessVersion;
use bitcoin::Network;
use miniscript::descriptor::DescriptorType;
use miniscript::policy::Concrete;
use miniscript::{Descriptor, Miniscript, Tap};
use secp256k1::{rand, KeyPair};

// Refer to https://github.com/sanket1729/adv_btc_workshop/blob/master/workshop.md#creating-a-taproot-descriptor
// for a detailed explanation of the policy and it's compilation

fn main() {
    let pubkeys = hardcoded_xonlypubkeys();
    let pol_str = format!(
        "or(
        99@thresh(2,
            pk({}),
            pk({})
        ),1@or(
            99@pk({}),
            1@and(pk({}),
            older(9))
            )
        )",
        pubkeys[0], pubkeys[1], pubkeys[2], pubkeys[3]
    )
    .replace(&[' ', '\n', '\t'][..], "");

    let pol: Concrete<bitcoin::XOnlyPublicKey> = Concrete::from_str(&pol_str).unwrap();

    // We require secp for generating a random XOnlyPublicKey
    let secp = secp256k1::Secp256k1::new();
    let key_pair = KeyPair::new(&secp, &mut rand::thread_rng());
    // Random unspendable XOnlyPublicKey provided for compilation to Taproot Descriptor
    let unspendable_key = bitcoin::XOnlyPublicKey::from_keypair(&key_pair);

    let private_desc = pol.compile_tr_private(Some(unspendable_key)).unwrap();
    // let opt_desc = pol.compile_tr(Some(unspendable_key.clone())).unwrap();
    let expected_desc = Descriptor::<bitcoin::XOnlyPublicKey>::from_str(&format!(
        "tr({},{{and_v(v:pk({}),older(9)),multi_a(2,{},{})}})",
        pubkeys[2], pubkeys[3], pubkeys[0], pubkeys[1]
    ))
    .unwrap();
    assert_eq!(private_desc, expected_desc);
    // assert_eq!(opt_desc, expected_desc);

    // Check whether the descriptors are safe.
    assert!(private_desc.sanity_check().is_ok());
    // assert!(opt_desc.sanity_check().is_ok());

    // Descriptor Type and Version should match respectively for Taproot
    let priv_desc_type = private_desc.desc_type();
    assert_eq!(priv_desc_type, DescriptorType::Tr);
    // let opt_desc_type = opt_desc.desc_type();
    // assert_eq!(opt_desc_type, DescriptorType::Tr);
    assert_eq!(priv_desc_type.segwit_version().unwrap(), WitnessVersion::V1);
    // assert_eq!(opt_desc_type.segwit_version().unwrap(), WitnessVersion::V1);

    if let Descriptor::Tr(ref p) = private_desc {
        // Check if internal key is correctly inferred as Ca
        assert_eq!(p.internal_key(), &pubkeys[2]);

        // Iterate through scripts
        let mut iter = p.iter_scripts();
        assert_eq!(
            iter.next().unwrap(),
            (
                1u8,
                &Miniscript::<bitcoin::XOnlyPublicKey, Tap>::from_str(&format!(
                    "and_v(vc:pk_k({}),older(9))",
                    pubkeys[3]
                ))
                .unwrap()
            )
        );
        assert_eq!(
            iter.next().unwrap(),
            (
                1u8,
                &Miniscript::<bitcoin::XOnlyPublicKey, Tap>::from_str(&format!(
                    "multi_a(2,{},{})",
                    pubkeys[0], pubkeys[1]
                ))
                .unwrap()
            )
        );
        assert_eq!(iter.next(), None);
    }

    // Max Satisfaction Weight for compilation, corresponding to the script-path spend
    // `multi_a(2,PUBKEY_1,PUBKEY_2) at taptree depth 1, having
    // Max Witness Size = scriptSig len + control_block size + varint(script_size) + script_size +
    //                     varint(max satisfaction elements) + max satisfaction size
    //                  = 4 + 65 + 1 + 70 + 1 + 132
    let max_sat_wt = private_desc.max_satisfaction_weight().unwrap();
    assert_eq!(max_sat_wt, 273);

    // Compute the bitcoin address and check if it matches
    let network = Network::Bitcoin;
    let priv_addr = private_desc.address(network).unwrap();
    let expected_addr = bitcoin::Address::from_str(
        "bc1pcc8ku64slu3wu04a6g376d2s8ck9y5alw5sus4zddvn8xgpdqw2swrghwx",
    )
    .unwrap();
    assert_eq!(priv_addr, expected_addr);
}

fn hardcoded_xonlypubkeys() -> Vec<bitcoin::XOnlyPublicKey> {
    let serialized_keys: [[u8; 32]; 4] = [
        [
            22, 37, 41, 4, 57, 254, 191, 38, 14, 184, 200, 133, 111, 226, 145, 183, 245, 112, 100,
            42, 69, 210, 146, 60, 179, 170, 174, 247, 231, 224, 221, 52,
        ],
        [
            194, 16, 47, 19, 231, 1, 0, 143, 203, 11, 35, 148, 101, 75, 200, 15, 14, 54, 222, 208,
            31, 205, 191, 215, 80, 69, 214, 126, 10, 124, 107, 154,
        ],
        [
            202, 56, 167, 245, 51, 10, 193, 145, 213, 151, 66, 122, 208, 43, 10, 17, 17, 153, 170,
            29, 89, 133, 223, 134, 220, 212, 166, 138, 2, 152, 122, 16,
        ],
        [
            50, 23, 194, 4, 213, 55, 42, 210, 67, 101, 23, 3, 195, 228, 31, 70, 127, 79, 21, 188,
            168, 39, 134, 58, 19, 181, 3, 63, 235, 103, 155, 213,
        ],
    ];
    let mut keys: Vec<bitcoin::XOnlyPublicKey> = vec![];
    for idx in 0..4 {
        keys.push(bitcoin::XOnlyPublicKey::from_slice(&serialized_keys[idx][..]).unwrap());
    }
    keys
}
