// Miniscript
// Written in 2019 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! # Policy Compiler
//!
//! Optimizing compiler from concrete policies to Miniscript
//!

use std::collections::HashMap;
use std::collections::hash_map;
use std::{cmp, f64};

use miniscript::types::{self, ErrorKind, Property, Type, Base};
use policy::Concrete;
use std::collections::vec_deque::VecDeque;
use std::hash;
use std::sync::Arc;
use Terminal;
use {Miniscript, MiniscriptKey};
use std::cmp::min;

#[derive(Copy, Clone, PartialEq, PartialOrd, Debug)]
pub struct OrdF64(f64);

impl Eq for OrdF64 {}
impl Ord for OrdF64 {
    fn cmp(&self, other: &OrdF64) -> cmp::Ordering {
        // will panic if given NaN
        self.0.partial_cmp(&other.0).unwrap()
    }
}

impl hash::Hash for OrdF64 {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct CompilationKey {
    ty: Type,

    expensive_verify: bool,

    dissat_prob: Option<OrdF64>,
}

impl CompilationKey {
    fn is_supertype(self, other: Self) -> bool {
        return self.ty.is_supertype(other.ty)
            && self.expensive_verify == other.expensive_verify
            && self.dissat_prob == other.dissat_prob;
    }

    fn from_type(ty: Type, expensive_verify: bool, dissat_prob: Option<f64>) -> CompilationKey {
        CompilationKey {
            ty: ty,
            expensive_verify: expensive_verify,
            dissat_prob: dissat_prob.and_then(|x| Some(OrdF64(x))),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct CompilerExtData {
    /// If this node is the direct child of a disjunction, this field must
    /// have the probability of its branch being taken. Otherwise it is ignored.
    /// All functions initialize it to `None`.
    branch_prob: Option<f64>,
    /// The number of bytes needed to satisfy the fragment in segwit format
    /// (total length of all witness pushes, plus their own length prefixes)
    sat_cost: f64,
    /// The number of bytes needed to dissatisfy the fragment in segwit format
    /// (total length of all witness pushes, plus their own length prefixes)
    /// for fragments that can be dissatisfied without failing the script.
    dissat_cost: Option<f64>,
}

impl Property for CompilerExtData {
    fn from_true() -> Self {
        // only used in casts. should never be computed directly
        unreachable!();
    }

    fn from_false() -> Self {
        CompilerExtData {
            branch_prob: Some(0.0),
            sat_cost: 0.0,
            dissat_cost: Some(0.0),
        }
    }

    fn from_pk() -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 73.0,
            dissat_cost: Some(1.0),
        }
    }

    fn from_pk_h() -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 73.0 + 34.0,
            dissat_cost: Some(1.0 + 34.0),
        }
    }

    fn from_multi(k: usize, _n: usize) -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 1.0 + 73.0 * k as f64,
            dissat_cost: Some(1.0 * (k + 1) as f64),
        }
    }

    fn from_hash() -> Self {
        // never called directly
        unreachable!()
    }

    fn from_sha256() -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 33.0,
            dissat_cost: Some(33.0),
        }
    }

    fn from_hash256() -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 33.0,
            dissat_cost: Some(33.0),
        }
    }

    fn from_ripemd160() -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 33.0,
            dissat_cost: Some(33.0),
        }
    }

    fn from_hash160() -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 33.0,
            dissat_cost: Some(33.0),
        }
    }

    fn from_time(_t: u32) -> Self {
        CompilerExtData {
            branch_prob: None,
            sat_cost: 0.0,
            dissat_cost: None,
        }
    }

    fn cast_alt(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: self.dissat_cost,
        })
    }

    fn cast_swap(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: self.dissat_cost,
        })
    }

    fn cast_check(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: self.dissat_cost,
        })
    }

    fn cast_dupif(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: 2.0 + self.sat_cost,
            dissat_cost: Some(1.0),
        })
    }

    fn cast_verify(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: None,
        })
    }

    fn cast_nonzero(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: Some(1.0),
        })
    }

    fn cast_zeronotequal(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: self.dissat_cost,
        })
    }

    fn cast_true(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: self.sat_cost,
            dissat_cost: None,
        })
    }

    fn cast_or_i_false(self) -> Result<Self, types::ErrorKind> {
        // never called directly
        unreachable!()
    }

    fn cast_unlikely(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: 2.0 + self.sat_cost,
            dissat_cost: Some(1.0),
        })
    }

    fn cast_likely(self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: 1.0 + self.sat_cost,
            dissat_cost: Some(2.0),
        })
    }

    fn and_b(left: Self, right: Self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: left.sat_cost + right.sat_cost,
            dissat_cost: match (left.dissat_cost, right.dissat_cost) {
                (Some(l), Some(r)) => Some(l + r),
                _ => None,
            },
        })
    }

    fn and_v(left: Self, right: Self) -> Result<Self, types::ErrorKind> {
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: left.sat_cost + right.sat_cost,
            dissat_cost: None,
        })
    }

    fn or_b(l: Self, r: Self) -> Result<Self, types::ErrorKind> {
        let lprob = l
            .branch_prob
            .expect("BUG: left branch prob must be set for disjunctions");
        let rprob = r
            .branch_prob
            .expect("BUG: right branch prob must be set for disjunctions");
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: lprob * (l.sat_cost + r.dissat_cost.unwrap())
                + rprob * (r.sat_cost + l.dissat_cost.unwrap()),
            dissat_cost: Some(l.dissat_cost.unwrap() + r.dissat_cost.unwrap()),
        })
    }

    fn or_d(l: Self, r: Self) -> Result<Self, types::ErrorKind> {
        let lprob = l
            .branch_prob
            .expect("BUG: left branch prob must be set for disjunctions");
        let rprob = r
            .branch_prob
            .expect("BUG: right branch prob must be set for disjunctions");
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: lprob * l.sat_cost + rprob * (r.sat_cost + l.dissat_cost.unwrap()),
            dissat_cost: r.dissat_cost.map(|rd| l.dissat_cost.unwrap() + rd),
        })
    }

    fn or_c(l: Self, r: Self) -> Result<Self, types::ErrorKind> {
        let lprob = l
            .branch_prob
            .expect("BUG: left branch prob must be set for disjunctions");
        let rprob = r
            .branch_prob
            .expect("BUG: right branch prob must be set for disjunctions");
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: lprob * l.sat_cost + rprob * (r.sat_cost + l.dissat_cost.unwrap()),
            dissat_cost: None,
        })
    }

    fn or_i(l: Self, r: Self) -> Result<Self, types::ErrorKind> {
        let lprob = l
            .branch_prob
            .expect("BUG: left branch prob must be set for disjunctions");
        let rprob = r
            .branch_prob
            .expect("BUG: right branch prob must be set for disjunctions");
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: lprob * (2.0 + l.sat_cost) + rprob * (1.0 + r.sat_cost),
            dissat_cost: if let (Some(ldis), Some(rdis)) = (l.dissat_cost, r.dissat_cost){
                if 2.0 + ldis > 1.0 + rdis{
                    Some(1.0 + rdis)
                } else{
                    Some(2.0 + ldis)
                }
            } else if let Some(ldis) = l.dissat_cost {
                Some(2.0 + ldis)
            } else if let Some(rdis) = r.dissat_cost {
                Some(1.0 + rdis)
            } else {
                None
            },
        })
    }

    fn and_or(a: Self, b: Self, c: Self) -> Result<Self, types::ErrorKind> {
        if a.dissat_cost.is_none() {
            return Err(ErrorKind::LeftNotDissatisfiable);
        }
        let aprob = a.branch_prob.unwrap_or(1.0);
        let bprob = b.branch_prob.unwrap_or(1.0);
        let cprob = c.branch_prob.unwrap_or(0.0);

        let adis = a
            .dissat_cost
            .expect("BUG: and_or first arg(a) must be dissatisfiable");
        debug_assert_eq!(aprob, bprob); //A and B must have same branch prob.
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: aprob * (a.sat_cost + b.sat_cost) + cprob * (adis + c.sat_cost),
            dissat_cost: if let Some(cdis) = c.dissat_cost {
                Some(adis + cdis)
            } else {
                None
            },
        })
    }

    //    fn and_n(a: Self, b: Self) -> Result<Self, types::ErrorKind> {
    //        Ok(CompilerExtData {
    //            branch_prob: None,
    //            sat_cost: aprob * (a.sat_cost + b.sat_cost) + cprob * (adis + c.sat_cost),
    //            dissat_cost: if let Some(bdis) = b.dissat_cost {
    //                Some(adis + bdis)
    //            } else if let Some(cdis) = c.dissat_cost {
    //                Some(adis + cdis)
    //            } else {
    //                None
    //            },
    //        })
    //    }

    fn threshold<S>(k: usize, n: usize, mut sub_ck: S) -> Result<Self, types::ErrorKind>
    where
        S: FnMut(usize) -> Result<Self, types::ErrorKind>,
    {
        let k_over_n = k as f64 / n as f64;
        let mut sat_cost = 0.0;
        let mut dissat_cost = 0.0;
        for i in 0..n {
            let sub = sub_ck(i)?;
            sat_cost += sub.sat_cost;
            dissat_cost += sub.dissat_cost.unwrap();
        }
        Ok(CompilerExtData {
            branch_prob: None,
            sat_cost: sat_cost * k_over_n + dissat_cost * (1.0 - k_over_n),
            dissat_cost: Some(dissat_cost),
        })
    }
}

/// Miniscript AST fragment with additional data needed by the compiler
#[derive(Clone, Debug)]
pub struct AstElemExt<Pk: MiniscriptKey> {
    /// The actual Miniscript fragment with type information
    pub ms: Arc<Miniscript<Pk>>,
    /// Its "type" in terms of compiler data
    pub comp_ext_data: CompilerExtData,
}

impl CompilerExtData {
    /// Compute a 1-dimensional cost, given a probability of satisfaction
    /// and a probability of dissatisfaction; if `dissat_prob` is `None`
    /// then it is assumed that dissatisfaction never occurs
    pub fn cost_1d(&self, pk_cost: usize, sat_prob: f64, dissat_prob: Option<f64>) -> f64 {
        pk_cost as f64
            + self.sat_cost * sat_prob
            + match (dissat_prob, self.dissat_cost) {
                (Some(prob), Some(cost)) => prob * cost,
                (Some(_), None) => 0.0,
                (None, Some(_)) => 0.0,
                (None, None) => 0.0,
            }
    }
}

impl<Pk: MiniscriptKey> AstElemExt<Pk> where {
    fn terminal(ast: Terminal<Pk>) -> AstElemExt<Pk> {
        AstElemExt {
            comp_ext_data: CompilerExtData::type_check(&ast, |_| None).unwrap(),
            ms: Arc::new(Miniscript::from_ast(ast).expect("Terminal creation must always succeed")),
        }
    }

    fn binary(
        ast: Terminal<Pk>,
        l: &AstElemExt<Pk>,
        r: &AstElemExt<Pk>,
    ) -> Result<AstElemExt<Pk>, types::Error<Pk>> {
        let lookup_ext = |n| match n {
            0 => Some(l.comp_ext_data),
            1 => Some(r.comp_ext_data),
            _ => unreachable!(),
        };
        //Types and ExtData are already cached and stored in children. So, we can
        //type_check without cache. For Compiler extra data, we supply a cache.
        let ty = types::Type::type_check(&ast, |_| None)?;
        let ext = types::ExtData::type_check(&ast, |_| None)?;
        let comp_ext_data = CompilerExtData::type_check(&ast, lookup_ext)?;
        Ok(AstElemExt {
            ms: Arc::new(Miniscript {
                ty: ty,
                ext: ext,
                node: ast,
            }),
            comp_ext_data: comp_ext_data,
        })
    }

    fn ternary(
        ast: Terminal<Pk>,
        a: &AstElemExt<Pk>,
        b: &AstElemExt<Pk>,
        c: &AstElemExt<Pk>,
    ) -> Result<AstElemExt<Pk>, types::Error<Pk>> {
        let lookup_ext = |n| match n {
            0 => Some(a.comp_ext_data),
            1 => Some(b.comp_ext_data),
            2 => Some(c.comp_ext_data),
            _ => unreachable!(),
        };
        //Types and ExtData are already cached and stored in children. So, we can
        //type_check without cache. For Compiler extra data, we supply a cache.
        let ty = types::Type::type_check(&ast, |_| None)?;
        let ext = types::ExtData::type_check(&ast, |_| None)?;
        let comp_ext_data = CompilerExtData::type_check(&ast, lookup_ext)?;
        Ok(AstElemExt {
            ms: Arc::new(Miniscript {
                ty: ty,
                ext: ext,
                node: ast,
            }),
            comp_ext_data: comp_ext_data,
        })
    }

    fn and_n(
        ast: Terminal<Pk>,
        a: &AstElemExt<Pk>,
        b: &AstElemExt<Pk>,
    ) -> Result<AstElemExt<Pk>, types::Error<Pk>> {
        let lookup_ext = |n| match n {
            0 => Some(a.comp_ext_data),
            1 => Some(b.comp_ext_data),
            2 => Some(CompilerExtData::from_false()),
            _ => unreachable!(),
        };
        //Types and ExtData are already cached and stored in children. So, we can
        //type_check without cache. For Compiler extra data, we supply a cache.
        let ty = types::Type::type_check(&ast, |_| None)?;
        let ext = types::ExtData::type_check(&ast, |_| None)?;
        let comp_ext_data = CompilerExtData::type_check(&ast, lookup_ext)?;
        Ok(AstElemExt {
            ms: Arc::new(Miniscript {
                ty: ty,
                ext: ext,
                node: ast,
            }),
            comp_ext_data: comp_ext_data,
        })
    }
}

#[derive(Copy, Clone)]
struct Cast<Pk: MiniscriptKey> {
    node: fn(Arc<Miniscript<Pk>>) -> Terminal<Pk>,
    ast_type: fn(types::Type) -> Result<types::Type, ErrorKind>,
    ext_data: fn(types::ExtData) -> Result<types::ExtData, ErrorKind>,
    comp_ext_data: fn(CompilerExtData) -> Result<CompilerExtData, types::ErrorKind>,
}

fn all_casts<Pk: MiniscriptKey>() -> [Cast<Pk>; 10] {
    [
        Cast {
            ext_data: types::ExtData::cast_check,
            node: Terminal::Check,
            ast_type: types::Type::cast_check,
            comp_ext_data: CompilerExtData::cast_check,
        },
        Cast {
            ext_data: types::ExtData::cast_dupif,
            node: Terminal::DupIf,
            ast_type: types::Type::cast_dupif,
            comp_ext_data: CompilerExtData::cast_dupif,
        },
        Cast {
            ext_data: types::ExtData::cast_unlikely,
            node: |ms| {
                Terminal::OrI(
                    ms,
                    Arc::new(
                        Miniscript::from_ast(Terminal::False).expect("False Miniscript creation"),
                    ),
                )
            },
            ast_type: types::Type::cast_unlikely,
            comp_ext_data: CompilerExtData::cast_unlikely,
        },
        Cast {
            ext_data: types::ExtData::cast_likely,
            node: |ms| {
                Terminal::OrI(
                    Arc::new(
                        Miniscript::from_ast(Terminal::False).expect("False Miniscript creation"),
                    ),
                    ms,
                )
            },
            ast_type: types::Type::cast_likely,
            comp_ext_data: CompilerExtData::cast_likely,
        },
        Cast {
            ext_data: types::ExtData::cast_verify,
            node: Terminal::Verify,
            ast_type: types::Type::cast_verify,
            comp_ext_data: CompilerExtData::cast_verify,
        },
        Cast {
            ext_data: types::ExtData::cast_nonzero,
            node: Terminal::NonZero,
            ast_type: types::Type::cast_nonzero,
            comp_ext_data: CompilerExtData::cast_nonzero,
        },
        Cast {
            ext_data: types::ExtData::cast_true,
            node: |ms| {
                Terminal::AndV(
                    ms,
                    Arc::new(
                        Miniscript::from_ast(Terminal::True).expect("True Miniscript creation"),
                    ),
                )
            },
            ast_type: types::Type::cast_true,
            comp_ext_data: CompilerExtData::cast_true,
        },
        Cast {
            ext_data: types::ExtData::cast_swap,
            node: Terminal::Swap,
            ast_type: types::Type::cast_swap,
            comp_ext_data: CompilerExtData::cast_swap,
        },
        Cast {
            node: Terminal::Alt,
            ast_type: types::Type::cast_alt,
            ext_data: types::ExtData::cast_alt,
            comp_ext_data: CompilerExtData::cast_alt,
        },
        Cast {
            ext_data: types::ExtData::cast_zeronotequal,
            node: Terminal::ZeroNotEqual,
            ast_type: types::Type::cast_zeronotequal,
            comp_ext_data: CompilerExtData::cast_zeronotequal,
        },
    ]
}

fn insert_best<Pk: MiniscriptKey>(
    map: &mut HashMap<CompilationKey, AstElemExt<Pk>>,
    key: CompilationKey,
    elem: AstElemExt<Pk>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) {
    match map.entry(key) {
        hash_map::Entry::Vacant(x) => {
            x.insert(elem);
        }
        hash_map::Entry::Occupied(mut x) => {
            let existing = x.get_mut();
            if elem
                .comp_ext_data
                .cost_1d(elem.ms.ext.pk_cost, sat_prob, dissat_prob)
                < existing
                .comp_ext_data
                .cost_1d(existing.ms.ext.pk_cost, sat_prob, dissat_prob)
            {
                *existing = elem;
            }
        }
    }
}

fn insert_best_wrapped_helper<Pk: MiniscriptKey>(
    map: &mut HashMap<CompilationKey, AstElemExt<Pk>>,
    data_vec: Vec<AstElemExt<Pk>>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) {
    let mut cast_stack: VecDeque<AstElemExt<Pk>> = VecDeque::new();
    for data in data_vec {
        if !data.ms.ty.mall.non_malleable {
            //        dbg!(&data);
            return;
        }

        let cost = data
            .comp_ext_data
            .cost_1d(data.ms.ext.pk_cost, sat_prob, dissat_prob);

        let current_key =
            CompilationKey::from_type(data.ms.ty, data.ms.ext.has_verify_form, dissat_prob);

        let better_type = map
            .iter()
            .map(|(key, elem)| {
                let elem_cost = elem
                    .comp_ext_data
                    .cost_1d(elem.ms.ext.pk_cost, sat_prob, dissat_prob);
                key.is_supertype(current_key) && elem_cost <= cost
            })
            .fold(false, |acc, x| acc || x);
//    if data.ms.ty.corr.base == Base::K && cost > 140.0 {
//        println!("K: {} {:?} {:?} {:?}", data.ms, sat_prob, dissat_prob, cost);
//    }
        if !better_type {
//                map.retain(
//                    |&key, elem| {
//                        let elem_cost = elem.comp_ext_data.cost_1d(elem.ms.ext.pk_cost, sat_prob, dissat_prob);
//                        !(current_key.is_supertype(key) && elem_cost >= cost)
//                    });
            //        dbg!(&map.get(&current_key));
//        if data.ms.ty.corr.base == Base::K {
//            let k = map.get(&current_key);
//            if k.is_some(){
//                let x = k.unwrap();
//                println!("K: {} {} {:?} {:?} {:?}", x.ms, data.ms, dissat_prob, cost,
//                         x.comp_ext_data.cost_1d(x.ms.ext.pk_cost, sat_prob, dissat_prob));
//            }
//        }
        map.insert(current_key, data.clone());
//            insert_best(map, current_key, data.clone(), sat_prob, dissat_prob);
    }
        cast_stack.push_back(data.clone());
    }

    let casts: [Cast<Pk>; 10] = all_casts::<Pk>();
    while !cast_stack.is_empty() {
        let current = cast_stack.pop_front().unwrap();

        //        dbg!(&current.ms);
        //        dbg!(&current);
        //        dbg!(&current
        //                 .comp_ext_data
        //                 .cost_1d(current.ms.ext.pk_cost, sat_prob, dissat_prob));

        //        if current.ms.ty.corr.base == Base::K && current.ms.ext.pk_cost >= 90 {
        //            dbg!(&current);
        //        }
        for i in 0..casts.len() {
            if let Ok(ms_type) = (casts[i].ast_type)(current.ms.ty) {
                if !ms_type.mall.non_malleable {
                                        dbg!(i);
                                        dbg!("maybe");
                    continue;
                }

                let comp_ext_data = (casts[i].comp_ext_data)(current.comp_ext_data)
                    .expect("if AST typeck passes then compiler ext typeck must");


                let ms_ext_data = (casts[i].ext_data)(current.ms.ext)
                    .expect("if AST typeck passes then ext typeck must");

                let cost_new = comp_ext_data.cost_1d(ms_ext_data.pk_cost, sat_prob, dissat_prob);

                let current_key =
                    CompilationKey::from_type(ms_type, ms_ext_data.has_verify_form, dissat_prob);

                let better_type = map
                    .iter()
                    .map(|(key, elem)| {
                        let elem_cost =
                            elem.comp_ext_data
                                .cost_1d(elem.ms.ext.pk_cost, sat_prob, dissat_prob);
                        key.is_supertype(current_key) && elem_cost <= cost_new

                    })
                    .fold(false, |acc, x| acc || x);

                if better_type {
                    continue;
                } else {
//                map.retain(
//                    |&key, elem| {
//                        let elem_cost = elem.comp_ext_data.cost_1d(elem.ms.ext.pk_cost, sat_prob, dissat_prob);
//                        !(current_key.is_supertype(key) && elem_cost > cost_new)
//                    });
                    let new_ext = AstElemExt {
                        ms: Arc::new(Miniscript {
                            node: (casts[i].node)(Arc::clone(&current.ms)),
                            ty: ms_type,
                            ext: ms_ext_data,
                        }),
                        comp_ext_data: comp_ext_data,
                    };
                    let new_key = CompilationKey::from_type(
                        new_ext.ms.ty,
                        new_ext.ms.ext.has_verify_form,
                        dissat_prob,
                    );
                    //                    dbg!(&map.get(&new_key));
                    //                    dbg!(cost);
//                    dbg!(map.get(&new_key));
                    if new_ext.ms.ty.corr.base == Base::B{
//                        let k = map.get(&new_key);
//                        if k.is_some() {
//                            let x = k.unwrap();
//                            println!("B: {} {} {:?} {:?}", x.ms, new_ext.ms, cost_new,
//                                     x.comp_ext_data.cost_1d(x.ms.ext.pk_cost, sat_prob, dissat_prob));
//                        }
                    }
                    map.insert(new_key, new_ext.clone());
//                    insert_best(map, new_key, new_ext.clone(), sat_prob, dissat_prob);
                    cast_stack.push_back(new_ext);
                }
            }
        }
    }
}

fn insert_best_wrapped<Pk: MiniscriptKey>(
    policy_cache: &mut HashMap<
        (Concrete<Pk>, OrdF64, Option<OrdF64>),
        HashMap<CompilationKey, AstElemExt<Pk>>,
    >,
    policy: &Concrete<Pk>,
    map: &mut HashMap<CompilationKey, AstElemExt<Pk>>,
    data: AstElemExt<Pk>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) {
//    insert_best_wrapped_helper(map, vec![data.clone()], sat_prob, None);
    if dissat_prob.is_some() {
        let mut y = vec![];
        for x in map.values() {
            y.push(x.clone());
        }
        insert_best_wrapped_helper(map, vec![data.clone()], sat_prob, dissat_prob);
    }
    insert_best_wrapped_helper(map, vec![data.clone()], sat_prob, None);
}

fn best_compilations<Pk>(
    policy_cache: &mut HashMap<
        (Concrete<Pk>, OrdF64, Option<OrdF64>),
        HashMap<CompilationKey, AstElemExt<Pk>>,
    >,
    policy: &Concrete<Pk>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) -> HashMap<CompilationKey, AstElemExt<Pk>>
where
    Pk: MiniscriptKey,
{
    let ord_sat_prob = OrdF64(sat_prob);
    let ord_dissat_prob = dissat_prob.and_then(|x| Some(OrdF64(x)));
    if let Some(ret) = policy_cache.get(&(policy.clone(), ord_sat_prob, ord_dissat_prob)) {
        return ret.clone();
    }
    println!("NEVER EVER {}{:?}{:?}", policy, sat_prob, dissat_prob);
    let mut ret = HashMap::new();
    match *policy {
        Concrete::Key(ref pk) => {
            insert_best_wrapped(
                policy_cache,
                policy,
                &mut ret,
                AstElemExt::terminal(Terminal::PkH(pk.to_pubkeyhash().clone())),
                sat_prob,
                dissat_prob,
            );
            insert_best_wrapped(
                policy_cache,
                policy,
                &mut ret,
                AstElemExt::terminal(Terminal::Pk(pk.clone())),
                sat_prob,
                dissat_prob,
            );
        }
        Concrete::After(n) => {
            insert_best_wrapped(
                policy_cache,
                policy,
                &mut ret,
                AstElemExt::terminal(Terminal::After(n)),
                sat_prob,
                dissat_prob,
            );
        }
        Concrete::Older(n) => {
            insert_best_wrapped(
                policy_cache,
                policy,
                &mut ret,
                AstElemExt::terminal(Terminal::Older(n)),
                sat_prob,
                dissat_prob,
            );
        }
        Concrete::Sha256(hash) => insert_best_wrapped(
            policy_cache,
            policy,
            &mut ret,
            AstElemExt::terminal(Terminal::Sha256(hash)),
            sat_prob,
            dissat_prob,
        ),
        Concrete::Hash256(hash) => insert_best_wrapped(
            policy_cache,
            policy,
            &mut ret,
            AstElemExt::terminal(Terminal::Hash256(hash)),
            sat_prob,
            dissat_prob,
        ),
        Concrete::Ripemd160(hash) => insert_best_wrapped(
            policy_cache,
            policy,
            &mut ret,
            AstElemExt::terminal(Terminal::Ripemd160(hash)),
            sat_prob,
            dissat_prob,
        ),
        Concrete::Hash160(hash) => insert_best_wrapped(
            policy_cache,
            policy,
            &mut ret,
            AstElemExt::terminal(Terminal::Hash160(hash)),
            sat_prob,
            dissat_prob,
        ),
        Concrete::And(ref subs) => {
            assert_eq!(subs.len(), 2, "and takes 2 args");
            let left = best_compilations(policy_cache, &subs[0], sat_prob, dissat_prob);
            let right = best_compilations(policy_cache, &subs[1], sat_prob, dissat_prob);
            for l in left.values() {
                let lref = Arc::clone(&l.ms);
                for r in right.values() {
                    #[derive(Clone)]
                    struct Try<'l, 'r, Pk: MiniscriptKey + 'l + 'r> {
                        left: &'l AstElemExt<Pk>,
                        right: &'r AstElemExt<Pk>,
                        ast: Terminal<Pk>,
                    }

                    impl<'l, 'r, Pk: MiniscriptKey + 'l + 'r> Try<'l, 'r, Pk> {
                        fn swap(self) -> Try<'r, 'l, Pk> {
                            Try {
                                left: self.right,
                                right: self.left,
                                ast: match self.ast {
                                    Terminal::AndB(l, r) => Terminal::AndB(r, l),
                                    Terminal::AndV(l, r) => Terminal::AndV(r, l),
                                    _ => unreachable!(),
                                },
                            }
                        }
                    }

                    let rref = Arc::clone(&r.ms);
                    let mut tries = [
                        Some(Terminal::AndB(Arc::clone(&lref), Arc::clone(&rref))),
                        Some(Terminal::AndV(Arc::clone(&lref), Arc::clone(&rref))),
                        // FIXME do and_n
                    ];
                    for opt in &mut tries {
                        let c = Try {
                            left: l,
                            right: r,
                            ast: opt.take().unwrap(),
                        };
                        let ast = c.ast.clone();
                        if let Ok(new_ext) = AstElemExt::binary(ast, c.left, c.right) {
                            insert_best_wrapped( policy_cache, policy,&mut ret, new_ext, sat_prob, dissat_prob);
                        }

                        let c = c.swap();
                        if let Ok(new_ext) = AstElemExt::binary(c.ast, c.left, c.right) {
                            insert_best_wrapped(                policy_cache,
                                                                policy,&mut ret, new_ext, sat_prob, dissat_prob);
                        }
                    }

                    let and_n = Terminal::AndOr(
                        Arc::clone(&lref),
                        Arc::clone(&rref),
                        Arc::new(
                            Miniscript::from_ast(Terminal::False)
                                .expect("False Miniscript creation"),
                        ),
                    );
                    if let Ok(new_ext) = AstElemExt::and_n(and_n, l, r) {
                        insert_best_wrapped(                policy_cache,
                                                            policy,&mut ret, new_ext, sat_prob, dissat_prob);
                    }
                    let and_n_s = Terminal::AndOr(
                        Arc::clone(&rref),
                        Arc::clone(&lref),
                        Arc::new(
                            Miniscript::from_ast(Terminal::False)
                                .expect("False Miniscript creation"),
                        ),
                    );
                    if let Ok(new_ext) = AstElemExt::and_n(and_n_s, r, l) {
                        insert_best_wrapped(                policy_cache,
                                                            policy,&mut ret, new_ext, sat_prob, dissat_prob);
                    }
                }
            }
        }
        Concrete::Or(ref subs) => {
            let total = (subs[0].0 + subs[1].0) as f64;
            let lw = subs[0].0 as f64 / total;
            let rw = subs[1].0 as f64 / total;

            //and-or
            if let (&Concrete::And(ref x), _) = (&subs[0].1, &subs[1].1) {
                let mut a1 = best_compilations(
                    policy_cache,
                    &x[0],
                    lw * sat_prob,
                    Some(dissat_prob.unwrap_or(0 as f64) + rw * sat_prob),
                );
                let mut a2 = best_compilations(policy_cache, &x[0], lw * sat_prob, None);

                let mut b1 = best_compilations(
                    policy_cache,
                    &x[1],
                    lw * sat_prob,
                    Some(dissat_prob.unwrap_or(0 as f64) + rw * sat_prob),
                );
                let mut b2 = best_compilations(policy_cache, &x[1], lw * sat_prob, None);

                let mut c = best_compilations(policy_cache, &subs[1].1, rw * sat_prob, dissat_prob);

                compile_and_or(
                    policy_cache,
                    policy,
                    &mut ret,
                    &mut a1,
                    &mut b2,
                    &mut c,
                    [lw, rw],
                    sat_prob,
                    dissat_prob,
                );
                compile_and_or(
                    policy_cache,
                    policy,
                    &mut ret,
                    &mut b1,
                    &mut a2,
                    &mut c,
                    [lw, rw],
                    sat_prob,
                    dissat_prob,
                );
            };
            if let (_, &Concrete::And(ref x)) = (&subs[0].1, &subs[1].1) {
                let mut a1 = best_compilations(
                    policy_cache,
                    &x[0],
                    rw * sat_prob,
                    Some(dissat_prob.unwrap_or(0 as f64) + lw * sat_prob),
                );
                let mut a2 = best_compilations(policy_cache, &x[0], rw * sat_prob, None);

                let mut b1 = best_compilations(
                    policy_cache,
                    &x[1],
                    rw * sat_prob,
                    Some(dissat_prob.unwrap_or(0 as f64) + lw * sat_prob),
                );
                let mut b2 = best_compilations(policy_cache, &x[1], rw * sat_prob, None);

                let mut c = best_compilations(policy_cache, &subs[0].1, lw * sat_prob, dissat_prob);

                compile_and_or(
                    policy_cache,
                    policy,
                    &mut ret,
                    &mut a1,
                    &mut b2,
                    &mut c,
                    [rw, lw],
                    sat_prob,
                    dissat_prob,
                );
                compile_and_or(
                    policy_cache,
                    policy,
                    &mut ret,
                    &mut b1,
                    &mut a2,
                    &mut c,
                    [rw, lw],
                    sat_prob,
                    dissat_prob,
                );
            };

            let dissat_probs = |w: f64| -> Vec<Option<f64>> {
                let mut dissat_set = Vec::new();
                dissat_set.push(Some(dissat_prob.unwrap_or(0 as f64) + w * sat_prob));
                dissat_set.push(Some(w * sat_prob));
                dissat_set.push(dissat_prob);
                dissat_set.push(None);
                dissat_set
            };

            let mut l_comp = vec![];
            let mut r_comp = vec![];

            for dissat_prob in dissat_probs(rw).iter() {
                let mut l =
                    best_compilations(policy_cache, &subs[0].1, lw * sat_prob, *dissat_prob);
                l_comp.push(l);
            }

            for dissat_prob in dissat_probs(lw).iter() {
                let mut r =
                    best_compilations(policy_cache, &subs[1].1, rw * sat_prob, *dissat_prob);
                r_comp.push(r);
            }
            compile_or(
                policy_cache,
                policy,
                &mut ret,
                &mut l_comp[0],
                &mut r_comp[0],
                [lw, rw],
                sat_prob,
                dissat_prob,
                Terminal::OrB,
            );
            compile_or(
                policy_cache,
                policy,
                &mut ret,
                &mut r_comp[0],
                &mut l_comp[0],
                [rw, lw],
                sat_prob,
                dissat_prob,
                Terminal::OrB,
            );

            compile_or(
                policy_cache,
                policy,
                &mut ret,
                &mut l_comp[0],
                &mut r_comp[2],
                [lw, rw],
                sat_prob,
                dissat_prob,
                Terminal::OrD,
            );
            compile_or(
                policy_cache,
                policy,
                &mut ret,
                &mut r_comp[0],
                &mut l_comp[2],
                [rw, lw],
                sat_prob,
                dissat_prob,
                Terminal::OrD,
            );

            compile_or(
                policy_cache,
                policy,
                &mut ret,
                &mut l_comp[1],
                &mut r_comp[3],
                [lw, rw],
                sat_prob,
                dissat_prob,
                Terminal::OrC,
            );
            compile_or(
                policy_cache,
                policy,
                &mut ret,
                &mut r_comp[3],
                &mut l_comp[1],
                [rw, lw],
                sat_prob,
                dissat_prob,
                Terminal::OrC,
            );

            compile_or(
                policy_cache,
                policy,
                &mut ret,
                &mut l_comp[2],
                &mut r_comp[3],
                [lw, rw],
                sat_prob,
                dissat_prob,
                Terminal::OrI,
            );
            compile_or(
                policy_cache,
                policy,
                &mut ret,
                &mut r_comp[2],
                &mut l_comp[3],
                [rw, lw],
                sat_prob,
                dissat_prob,
                Terminal::OrI,
            );

            compile_or(
                policy_cache,
                policy,
                &mut ret,
                &mut l_comp[3],
                &mut r_comp[2],
                [lw, rw],
                sat_prob,
                dissat_prob,
                Terminal::OrI,
            );
            compile_or(
                policy_cache,
                policy,
                &mut ret,
                &mut r_comp[3],
                &mut l_comp[2],
                [rw, lw],
                sat_prob,
                dissat_prob,
                Terminal::OrI,
            );
        }
        Concrete::Threshold(k, ref subs) => {
            let n = subs.len();
            let k_over_n = k as f64 / n as f64;

            let mut sub_ast = Vec::with_capacity(n);
            let mut sub_ext_data = Vec::with_capacity(n);

            let mut best_es = Vec::with_capacity(n);
            let mut best_ws = Vec::with_capacity(n);

            let mut min_value = (0 as usize, f64::INFINITY as f64);
            for (i, ast) in subs.iter().enumerate() {
                let sp = sat_prob * k_over_n;
                //Expressions must be dissatisfiable
                let dp = Some(dissat_prob.unwrap_or(0 as f64) + (1.0 - k_over_n) * sat_prob);
                //                dbg!(dp);
                let be = best_e(policy_cache, ast, sp, dp);
                let we = best_w(policy_cache, ast, sp, dp);

                let mut diff = be
                    .comp_ext_data
                    .cost_1d(be.ms.ext.pk_cost, sp, dp)
                    - we.comp_ext_data
                        .cost_1d(we.ms.ext.pk_cost, sp, dp);

                best_es.push((be.clone(), be.comp_ext_data));
                best_ws.push((we.clone(), we.comp_ext_data));

                if diff < min_value.1 {
                    min_value.0 = i;
                    min_value.1 = diff;
                }
            }
            sub_ast.push(best_es[min_value.0].0.ms.clone());
            sub_ext_data.push(best_es[min_value.0].1);
            for (i, _ast) in subs.iter().enumerate() {
                if i != min_value.0 {
                    sub_ast.push(best_ws[i].0.ms.clone());
                    sub_ext_data.push(best_ws[i].1);
                }
            }
            let ast = Terminal::Thresh(k, sub_ast);
            let ast_ext = AstElemExt {
                ms: Arc::new(
                    Miniscript::from_ast(ast)
                        .expect("threshold subs, which we just compiled, typeck"),
                ),
                comp_ext_data: CompilerExtData::threshold(k, n, |i| Ok(sub_ext_data[i]))
                    .expect("threshold subs, which we just compiled, typeck"),
            };
            //            println!("{} {:?} {:?}", ast_ext.ms, sat_prob, dissat_prob);
            insert_best_wrapped(                policy_cache,
                                                policy,&mut ret, ast_ext, sat_prob, dissat_prob);

            let key_vec: Vec<Pk> = subs
                .iter()
                .filter_map(|s| {
                    if let Concrete::Key(ref pk) = *s {
                        Some(pk.clone())
                    } else {
                        None
                    }
                })
                .collect();
            if key_vec.len() == subs.len() && subs.len() <= 20 {
                insert_best_wrapped(
                    policy_cache,
                    policy,
                    &mut ret,
                    AstElemExt::terminal(Terminal::ThreshM(k, key_vec)),
                    sat_prob,
                    dissat_prob,
                );
            }
        }
    }
    policy_cache.insert((policy.clone(), ord_sat_prob, ord_dissat_prob), ret.clone());
    ret
}

pub fn best_compilation<Pk: MiniscriptKey>(policy: &Concrete<Pk>) -> Miniscript<Pk> {
    let mut policy_cache = HashMap::new();
    let x = &*best_t(&mut policy_cache, policy, 1.0, None).ms;
    x.clone()
}
/// Helper function to compile different types of or fragments.
/// `sat_prob` and `dissat_prob` represent the sat and dissat probabilities of
/// root or. `weights` represent the odds for taking each sub branch
fn compile_or<Pk, F>(
    policy_cache: &mut HashMap<
        (Concrete<Pk>, OrdF64, Option<OrdF64>),
        HashMap<CompilationKey, AstElemExt<Pk>>,
    >,
    policy: &Concrete<Pk>,
    ret: &mut HashMap<CompilationKey, AstElemExt<Pk>>,
    left_comp: &mut HashMap<CompilationKey, AstElemExt<Pk>>,
    right_comp: &mut HashMap<CompilationKey, AstElemExt<Pk>>,
    weights: [f64; 2],
    sat_prob: f64,
    dissat_prob: Option<f64>,
    or_type: F,
) where
    Pk: MiniscriptKey,
    F: Fn(Arc<Miniscript<Pk>>, Arc<Miniscript<Pk>>) -> Terminal<Pk>,
{
    for l in left_comp.values_mut() {
        let lref = Arc::clone(&l.ms);
        for r in right_comp.values_mut() {
            let rref = Arc::clone(&r.ms);
            let mut ast = or_type(Arc::clone(&lref), Arc::clone(&rref));
            l.comp_ext_data.branch_prob = Some(weights[0]);
            r.comp_ext_data.branch_prob = Some(weights[1]);
            if let Ok(new_ext) = AstElemExt::binary(ast, l, r) {
                insert_best_wrapped(
                    policy_cache,
                    policy,ret, new_ext, sat_prob, dissat_prob);
            }
        }
    }
}

/// Helper function to compile different order of and_or fragments.
/// `sat_prob` and `dissat_prob` represent the sat and dissat probabilities of
/// root and_or node. `weights` represent the odds for taking each sub branch
fn compile_and_or<Pk: MiniscriptKey>(
    policy_cache: &mut HashMap<
        (Concrete<Pk>, OrdF64, Option<OrdF64>),
        HashMap<CompilationKey, AstElemExt<Pk>>,
    >,
    policy: &Concrete<Pk>,
    ret: &mut HashMap<CompilationKey, AstElemExt<Pk>>,
    a_comp: &mut HashMap<CompilationKey, AstElemExt<Pk>>,
    b_comp: &mut HashMap<CompilationKey, AstElemExt<Pk>>,
    c_comp: &mut HashMap<CompilationKey, AstElemExt<Pk>>,
    weights: [f64; 2],
    sat_prob: f64,
    dissat_prob: Option<f64>,
) {
    for a in a_comp.values_mut() {
        let aref = Arc::clone(&a.ms);
        for b in b_comp.values_mut() {
            let bref = Arc::clone(&b.ms);
            for c in c_comp.values_mut() {
                let cref = Arc::clone(&c.ms);
                let mut ast =
                    Terminal::AndOr(Arc::clone(&aref), Arc::clone(&bref), Arc::clone(&cref));
                a.comp_ext_data.branch_prob = Some(weights[0]);
                b.comp_ext_data.branch_prob = Some(weights[0]);
                c.comp_ext_data.branch_prob = Some(weights[1]);
                if let Ok(new_ext) = AstElemExt::ternary(ast, a, b, c) {
                    insert_best_wrapped(
                        policy_cache,
                        policy,
                        ret, new_ext, sat_prob, dissat_prob);
                }
            }
        }
    }
}

pub fn best_t<Pk>(
    policy_cache: &mut HashMap<
        (Concrete<Pk>, OrdF64, Option<OrdF64>),
        HashMap<CompilationKey, AstElemExt<Pk>>,
    >,
    policy: &Concrete<Pk>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) -> AstElemExt<Pk>
where
    Pk: MiniscriptKey,
{
    best_compilations(policy_cache, policy, sat_prob, dissat_prob)
        .into_iter()
        .filter(|&(key, _)|
            key.ty.corr.base == types::Base::B
                && key.dissat_prob == dissat_prob.and_then(|x| Some(OrdF64(x)))
        )
        .map(|(_, val)| val)
        .min_by_key(|ext| {
            OrdF64(
                ext.comp_ext_data
                    .cost_1d(ext.ms.ext.pk_cost, sat_prob, dissat_prob),
            )
        })
        .unwrap()
}

pub fn best_e<Pk>(
    policy_cache: &mut HashMap<
        (Concrete<Pk>, OrdF64, Option<OrdF64>),
        HashMap<CompilationKey, AstElemExt<Pk>>,
    >,
    policy: &Concrete<Pk>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) -> AstElemExt<Pk>
where
    Pk: MiniscriptKey,
{
    //    dbg!(best_compilations(policy_cache, policy, sat_prob, dissat_prob));
    //    dbg!(&policy);
    //    dbg!(sat_prob);
    //    dbg!(dissat_prob);
    best_compilations(policy_cache, policy, sat_prob, dissat_prob)
        .into_iter()
        .filter(|&(ref key, ref val)| {
            key.ty.corr.base == types::Base::B
                && key.ty.corr.unit
                && val.ms.ty.mall.dissat == types::Dissat::Unique
        })
        .map(|(_, val)| val)
        .min_by_key(|ext| {
            OrdF64(
                ext.comp_ext_data
                    .cost_1d(ext.ms.ext.pk_cost, sat_prob, dissat_prob),
            )
        })
        .unwrap()
}

fn best_w<Pk>(
    policy_cache: &mut HashMap<
        (Concrete<Pk>, OrdF64, Option<OrdF64>),
        HashMap<CompilationKey, AstElemExt<Pk>>,
    >,
    policy: &Concrete<Pk>,
    sat_prob: f64,
    dissat_prob: Option<f64>,
) -> AstElemExt<Pk>
where
    Pk: MiniscriptKey,
{
    //    println!("{:?} test", best_compilations(policy, sat_prob, dissat_prob)
    //    );
    //    println!("esrds");
    //    dbg!("temp");
    best_compilations(policy_cache, policy, sat_prob, dissat_prob)
        .into_iter()
        .filter(|&(ref key, ref val)| {
            key.ty.corr.base == types::Base::W
                && key.ty.corr.unit
                && val.ms.ty.mall.dissat == types::Dissat::Unique
        })
        .map(|(_, val)| val)
        .min_by_key(|ext| {
            OrdF64(
                ext.comp_ext_data
                    .cost_1d(ext.ms.ext.pk_cost, sat_prob, dissat_prob),
            )
        })
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::blockdata::{opcodes, script};
    use secp256k1;
    use std::str::FromStr;
    use {bitcoin, ToPublicKey};

    use hex_script;
    use policy::{Liftable, Semantic};
    use BitcoinSig;
    use DummyKey;
    use DummyKeyHash;
    use Satisfier;
    use policy::concrete::Policy;

    type SPolicy = Concrete<String>;
    type DummyPolicy = Concrete<DummyKey>;
    type BPolicy = Concrete<bitcoin::PublicKey>;

    fn pubkeys_and_a_sig(n: usize) -> (Vec<bitcoin::PublicKey>, secp256k1::Signature) {
        let mut ret = Vec::with_capacity(n);
        let secp = secp256k1::Secp256k1::new();
        let mut sk = [0; 32];
        for i in 1..n + 1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let pk = bitcoin::PublicKey {
                key: secp256k1::PublicKey::from_secret_key(
                    &secp,
                    &secp256k1::SecretKey::from_slice(&sk[..]).expect("sk"),
                ),
                compressed: true,
            };
            ret.push(pk);
        }
        let sig = secp.sign(
            &secp256k1::Message::from_slice(&sk[..]).expect("secret key"),
            &secp256k1::SecretKey::from_slice(&sk[..]).expect("secret key"),
        );
        (ret, sig)
    }

    #[test]
    fn compile_basic() {
        let policy = Policy::<String>::from_str(
            "or(and(pk(C),pk(C)),or(3@or(pk(C),3@and(or(or(3@and(after(9),pk(C)),pk(C)),99@after(9)),or(or(pk(C),pk(C)),3@pk(C)))),99@and(pk(C),and(pk(C),pk(C)))))").expect("parse");
        let compilation = best_t(
            &mut HashMap::new(),
            &policy,
            0.000006893382352941177,
            Some(0.5404434742647058),
        );

        dbg!(&compilation);

        println!("{}", &compilation.ms);
        println!(
            "{:?} {}",
            &compilation.ms.ext,
            compilation.comp_ext_data.cost_1d(
                compilation.ms.ext.pk_cost,
                1.0,
                None,
            )
        );
        //        let miniscript = policy.compile();
        //        assert_eq!(policy.into_lift(), Semantic::KeyHash(DummyKeyHash));
        //        assert_eq!(miniscript.into_lift(), Semantic::KeyHash(DummyKeyHash));
    }

    #[test]
    fn compile_q() {
        let policy = SPolicy::from_str("or(pk(C),pk(C))").expect("parsing");
        let compilation = best_t(&mut HashMap::new(), &policy, 1.0, None);

        dbg!(&compilation);
        assert_eq!(
            compilation
                .comp_ext_data
                .cost_1d(compilation.ms.ext.pk_cost, 1.0, None),
            88.0 + 74.109375
        );
        assert_eq!(
            policy.into_lift().sorted(),
            compilation.ms.into_lift().sorted()
        );

        let policy = SPolicy::from_str(
            "and(and(and(or(127@thresh(2,pk(),pk(),thresh(2,or(127@pk(),1@pk()),after(100),or(and(pk(),after(200)),and(pk(),sha256(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925))),pk())),1@pk()),sha256(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925)),or(127@pk(),1@after(300))),or(127@after(400),pk()))"
        ).expect("parsing");
        let compilation = best_t(&mut HashMap::new(), &policy, 1.0, None);

        assert_eq!(
            compilation
                .comp_ext_data
                .cost_1d(compilation.ms.ext.pk_cost, 1.0, None),
            437.0 + 299.7310587565105
        );
        assert_eq!(
            policy.into_lift().sorted(),
            compilation.ms.into_lift().sorted()
        );
    }

    #[test]
    fn compile_misc() {
        let (keys, sig) = pubkeys_and_a_sig(10);
        let key_pol: Vec<BPolicy> = keys.iter().map(|k| Concrete::Key(*k)).collect();
        let policy: BPolicy = Concrete::After(100);
        let desc = policy.compile();
        assert_eq!(desc.encode(), hex_script("0164b2"));

        let policy: BPolicy = Concrete::Key(keys[0].clone());
        let desc = policy.compile();
        assert_eq!(
            desc.encode(),
            script::Builder::new()
                .push_key(&keys[0])
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script()
        );

        // CSV reordering trick
        let policy: BPolicy = policy_str!(
            "and(after(10000),thresh(2,pk({}),pk({}),pk({})))",
            keys[5],
            keys[6],
            keys[7]
        );
        let desc = policy.compile();
        assert_eq!(
            desc.encode(),
            script::Builder::new()
                .push_opcode(opcodes::all::OP_PUSHNUM_2)
                .push_key(&keys[5])
                .push_key(&keys[6])
                .push_key(&keys[7])
                .push_opcode(opcodes::all::OP_PUSHNUM_3)
                .push_opcode(opcodes::all::OP_CHECKMULTISIGVERIFY)
                .push_int(10000)
                .push_opcode(opcodes::OP_CSV)
                .into_script()
        );

        // Liquid policy
        let policy: BPolicy = Concrete::Or(vec![
            (127, Concrete::Threshold(3, key_pol[0..5].to_owned())),
            (
                1,
                Concrete::And(vec![
                    Concrete::After(10000),
                    Concrete::Threshold(2, key_pol[5..8].to_owned()),
                ]),
            ),
        ]);

        let desc = policy.compile();

        let ms: Miniscript<bitcoin::PublicKey> = ms_str!(
            "or_d(thresh_m(3,{},{},{},{},{}),\
             and_v(v:thresh(2,c:pk_h({}),\
             ac:pk_h({}),ac:pk_h({})),after(10000)))",
            keys[0],
            keys[1],
            keys[2],
            keys[3],
            keys[4],
            keys[5].to_pubkeyhash(),
            keys[6].to_pubkeyhash(),
            keys[7].to_pubkeyhash()
        );

        assert_eq!(desc, ms);

        //        let mut abs = policy.into_lift();
        //        assert_eq!(abs.n_keys(), 8);
        //        assert_eq!(abs.minimum_n_keys(), 2);
        //        abs = abs.at_age(10000);
        //        assert_eq!(abs.n_keys(), 8);
        //        assert_eq!(abs.minimum_n_keys(), 2);
        //        abs = abs.at_age(9999);
        //        assert_eq!(abs.n_keys(), 5);
        //        assert_eq!(abs.minimum_n_keys(), 3);
        //        abs = abs.at_age(0);
        //        assert_eq!(abs.n_keys(), 5);
        //        assert_eq!(abs.minimum_n_keys(), 3);
        //
        //        let mut sigvec = sig.serialize_der();
        //        sigvec.push(1); // sighash all
        //
        //        struct BadSat;
        //        struct GoodSat(secp256k1::Signature);
        //        struct LeftSat<'a>(&'a [bitcoin::PublicKey], secp256k1::Signature);
        //
        //        impl<Pk: MiniscriptKey> Satisfier<Pk> for BadSat {}
        //        impl<Pk: MiniscriptKey> Satisfier<Pk> for GoodSat {
        //            fn lookup_pk(&self, _: &Pk) -> Option<BitcoinSig> {
        //                Some((self.0, bitcoin::SigHashType::All))
        //            }
        //        }
        //        impl<'a> Satisfier<bitcoin::PublicKey> for LeftSat<'a> {
        //            fn lookup_pk(&self, pk: &bitcoin::PublicKey) -> Option<BitcoinSig> {
        //                for (n, target_pk) in self.0.iter().enumerate() {
        //                    if pk == target_pk && n < 5 {
        //                        return Some((self.1, bitcoin::SigHashType::All));
        //                    }
        //                }
        //                None
        //            }
        //            fn lookup_pkh(&self, pk: &bitcoin::PublicKey) -> Option<BitcoinSig> {
        //                for (n, target_pk) in self.0.iter().enumerate() {
        //                    if pk == target_pk && n < 5 {
        //                        return Some((self.1, bitcoin::SigHashType::All));
        //                    }
        //                }
        //                None
        //            }
        //        }
        //
        //        assert!(desc.satisfy(&BadSat, 0, 0).is_none());
        //        assert!(desc.satisfy(&GoodSat(sig), 0, 0).is_some());
        //        assert!(desc.satisfy(&LeftSat(&keys[..], sig), 0, 0).is_some());
        //
        //        assert_eq!(
        //            desc.satisfy(&LeftSat(&keys[..], sig), 0, 0).unwrap(),
        //            vec![
        //                // sat for left branch
        //                vec![],
        //                sigvec.clone(),
        //                sigvec.clone(),
        //                sigvec.clone(),
        //            ]
        //        );
        //
        //        assert_eq!(
        //            desc.satisfy(&GoodSat(sig), 10000, 0).unwrap(),
        //            vec![
        //                // sat for right branch
        //                vec![],
        //                keys[7].to_bytes(),
        //                sigvec.clone(),
        //                keys[6].to_bytes(),
        //                sigvec.clone(),
        //                keys[5].to_bytes(),
        //                // dissat for left branch
        //                vec![],
        //                vec![],
        //                vec![],
        //                vec![],
        //            ]
        //        );
    }
}

#[cfg(all(test, feature = "unstable"))]
mod benches {
    use secp256k1;
    use std::str::FromStr;
    use test::{black_box, Bencher};

    use Concrete;
    use ParseTree;

    #[bench]
    pub fn compile(bh: &mut Bencher) {
        let desc = Concrete::<secp256k1::PublicKey>::from_str(
            "and(thresh(2,and(sha256(),or(sha256(),pk())),pk(),pk(),pk(),sha256()),pkh())",
        )
        .expect("parsing");
        bh.iter(|| {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }

    #[bench]
    pub fn compile_large(bh: &mut Bencher) {
        let desc = Concrete::<secp256k1::PublicKey>::from_str(
            "or(pkh(),thresh(9,sha256(),pkh(),pk(),and(or(pkh(),pk()),pk()),time_e(),pk(),pk(),pk(),pk(),and(pk(),pk())))"
        ).expect("parsing");
        bh.iter(|| {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }

    #[bench]
    pub fn compile_xlarge(bh: &mut Bencher) {
        let desc = Concrete::<secp256k1::PublicKey>::from_str(
            "or(pk(),thresh(4,pkh(),time_e(),multi(),and(after(),or(pkh(),or(pkh(),and(pkh(),thresh(2,multi(),or(pkh(),and(thresh(5,sha256(),or(pkh(),pkh()),pkh(),pkh(),pkh(),multi(),pkh(),multi(),pk(),pkh(),pk()),pkh())),pkh(),or(and(pkh(),pk()),pk()),after()))))),pkh()))"
        ).expect("parsing");
        bh.iter(|| {
            let pt = ParseTree::compile(&desc);
            black_box(pt);
        });
    }
}
