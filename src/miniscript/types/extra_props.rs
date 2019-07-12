//! Other miscellaneous type properties which are not related to
//! correctness or malleability.

use super::{ErrorKind, Property};

/// Whether a fragment is OK to be used in non-segwit scripts
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum LegacySafe {
    /// The fragment can be used in pre-segwit contexts without concern
    /// about malleability attacks/unbounded 3rd-party fee stuffing. This
    /// means it has no `pk_h` constructions (cannot estimate public key
    /// size from a hash) and no `d:`/`or_i` constructions (cannot control
    /// the size of the switch input to `OP_IF`)
    LegacySafe,
    /// This fragment can only be safely used with Segwit
    SegwitOnly,
}

/// Structure representing the extra type properties of a fragment which are
/// relevant to legacy(pre-segwit) safety and fee estimation. If a fragment is
/// used in pre-segwit transactions it will only be malleable but still is
/// correct and sound.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ExtData{
    ///enum sorting whether the fragment is safe to be in used in pre-segwit context
    legacy_safe: LegacySafe,
    /// The number of bytes needed to encode its scriptpubkey
    pk_cost: usize,
    /// Whether this fragment can be verify-wrapped for free
    has_verify_form: bool,
}

impl Property for ExtData {
    fn sanity_checks(&self) {
        //No sanity checks
    }

    fn from_true() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 1,
            has_verify_form: false,
        }
    }

    fn from_false() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 1,
            has_verify_form: false,
        }
    }

    fn from_pk() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 34,
            has_verify_form: false,
        }
    }

    fn from_pk_h() -> Self {
        ExtData {
            legacy_safe: LegacySafe::SegwitOnly,
            pk_cost: 24,
            has_verify_form: false,
        }
    }

    fn from_multi(k: usize, n: usize) -> Self {
        let num_cost = match(k > 16, n > 16) {
            (true, true) => 4,
            (false, true) => 3,
            (true, false) => 3,
            (false, false) => 2,
        };
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: num_cost + 34 * n + 1,
            has_verify_form: true,
        }
    }

    fn from_hash() -> Self {
        //never called directly
        unreachable!()
    }

    fn from_sha256() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 33 + 6,
            has_verify_form: true,
        }
    }

    fn from_hash256() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 33 + 6,
            has_verify_form: true,
        }
    }

    fn from_ripemd160() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 21 + 6,
            has_verify_form: true,
        }
    }

    fn from_hash160() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 21 + 6,
            has_verify_form: true,
        }
    }

    fn from_time(t: u32) -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: script_num_cost(t) + 1,
            has_verify_form: false,
        }
    }
    fn cast_alt(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 2,
            has_verify_form: false,
        })
    }

    fn cast_swap(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 1,
            has_verify_form: self.has_verify_form,
        })
    }

    fn cast_check(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 1,
            has_verify_form: true,
        })
    }

    fn cast_dupif(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: LegacySafe::SegwitOnly,
            pk_cost: self.pk_cost + 3,
            has_verify_form: false,
        })
    }

    fn cast_verify(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + if self.has_verify_form { 0 } else { 1 },
            has_verify_form: false,
        })
    }

    fn cast_nonzero(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 4,
            has_verify_form: false,
        })
    }

    fn cast_zeronotequal(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 1,
            has_verify_form: false,
        })
    }

    fn cast_true(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 1,
            has_verify_form: false,
        })
    }

    fn cast_or_i_false(self) -> Result<Self, ErrorKind> {
        // never called directly
        unreachable!()
    }

    fn cast_unlikely(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 4,
            has_verify_form: false,
        })
    }

    fn cast_likely(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 4,
            has_verify_form: false,
        })
    }

    fn and_b(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost + 1,
            has_verify_form: false,
        })
    }

    fn and_v(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost,
            has_verify_form: r.has_verify_form,
        })
    }

    fn or_b(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost + 1,
            has_verify_form: false,
        })
    }

    fn or_d(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: LegacySafe::SegwitOnly,
            pk_cost: l.pk_cost + r.pk_cost + 3,
            has_verify_form: l.has_verify_form && r.has_verify_form,
        })
    }

    fn or_c(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost + 2,
            has_verify_form: false,
        })
    }

    fn or_i(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost + 3,
            has_verify_form: l.has_verify_form && r.has_verify_form,
        })
    }

    fn and_or(_a: Self, _b: Self, _c: Self) -> Result<Self, ErrorKind> {
        unimplemented!("compiler doesn't support andor yet")
    }

    fn threshold<S>(
        k: usize,
        n: usize,
        mut sub_ck: S,
    ) -> Result<Self, ErrorKind>
        where S: FnMut(usize) -> Result<Self, ErrorKind>
    {
        let mut pk_cost = 1 + script_num_cost(k as u32);
        let mut legacy_safe = LegacySafe::LegacySafe;
        for i in 0..n {

            let sub = sub_ck(i)?;
            pk_cost += sub.pk_cost;
            legacy_safe = legacy_safe2(legacy_safe, sub.legacy_safe);
        }
        Ok(ExtData {
            legacy_safe: legacy_safe,
            pk_cost: pk_cost,
            has_verify_form: true,
        })
    }
}

fn legacy_safe2(a: LegacySafe, b: LegacySafe) -> LegacySafe{
    match (a,b){
        (LegacySafe::LegacySafe, LegacySafe::LegacySafe) => LegacySafe::LegacySafe,
        _ => LegacySafe::SegwitOnly
    }
}

fn script_num_cost(n: u32) -> usize {
    if n <= 16 {
        1
    } else if n < 0x80 {
        2
    } else if n < 0x8000 {
        3
    } else if n < 0x800000 {
        4
    } else {
        5
    }
}
