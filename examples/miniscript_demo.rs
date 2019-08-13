//! Example: Compiler output.

extern crate bitcoin;
extern crate miniscript;
extern crate secp256k1;

use miniscript::policy::concrete::Policy;
use miniscript::Descriptor;
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

fn main() {
    //    let (pks, der_sigs, secp_sigs, sighash, secp) = setup_keys_sigs(53);

    //Without any probabilities.

    let good_case = thresh_str(35, 50);

    println!("Good case:\n  {} \n \n ", good_case);

    let emergency_path =
        Policy::<String>::from_str("and(thresh(2,pk(E0),pk(E1),pk(E2)),after(4032))").unwrap();

    println!("Emergency path \n {} \n\n\n", emergency_path);
    // We can easily compose policies.
    let liquid_policy =
        Policy::<String>::from_str(&format!("or({},{})", good_case, emergency_path)).unwrap();

    println!(
        "Now, let's compose the policies \n \n {} \n \n",
        liquid_policy
    );

    let liquid_ms = liquid_policy.compile().unwrap();
    let liq_des = Descriptor::Wsh(liquid_ms);

    println!(
        "Let's compile and embed into descriptor \n\n {} \n\n",
        liq_des
    );
    // We can also assign probabilities.
    let liquid_policy =
        Policy::<String>::from_str(&format!("or(999@{},1@{})", good_case, emergency_path)).unwrap();

    println!(
        "Now, let's compose again, but with probabilities \n \n {} \n \n",
        liquid_policy
    );
    let liquid_ms = liquid_policy.compile().unwrap();
    let liq_des = Descriptor::Wsh(liquid_ms);
    println!(
        "Let's compile and embed into descriptor \n\n {} \n\n",
        liq_des
    );
}
