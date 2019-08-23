// Miniscript
// Written in 2019 by
//    Thomas Eizinger <thomas@coblox.tech>
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

//! Example: Create an HTLC with miniscript

extern crate bitcoin;
extern crate miniscript;

use miniscript::policy::Concrete;
use miniscript::Descriptor;
use std::str::FromStr;
use miniscript::Miniscript;

fn main() {
    //HTLC policy with 10:1 odds for happy(co-operative) case compared to uncooperative case
    let htlc_policy = Concrete::from_str(&format!("or(10@and(sha256({secret_hash}),pk({redeem_identity})),1@and(older({expiry}),pk({refund_identity})))",
        secret_hash = "1111111111111111111111111111111111111111111111111111111111111111",
        redeem_identity = "022222222222222222222222222222222222222222222222222222222222222222",
        refund_identity = "022222222222222222222222222222222222222222222222222222222222222222",
        expiry = "4444"
    )).unwrap();

    let htlc_miniscript: Miniscript::<bitcoin::PublicKey> = htlc_policy.compile().unwrap();

    let htlc_descriptor = Descriptor::Wsh(htlc_miniscript);

    println!("{}", htlc_descriptor);
}
