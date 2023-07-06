#![cfg_attr(feature = "cargo-clippy", deny(warnings))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::unreadable_literal))]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![feature(test)]

/*!
 This crate has utilities to test bls_sigs_ref
*/

extern crate bls_sigs_ref;
extern crate pairing_plus;
extern crate sha2;
extern crate test as testbench;

#[cfg(test)]
mod test;

#[cfg(test)]
mod bench;

mod testvec;

use bls_sigs_ref::{BLSSignatureAug, BLSSignatureBasic, BLSSignaturePop};
use pairing_plus::hash_to_curve::HashToCurve;
use pairing_plus::hash_to_field::ExpandMsgXmd;
use pairing_plus::serdes::SerDes;
use pairing_plus::CurveProjective;
use sha2::Sha256;
use std::io::{Cursor, Result};
use testbench::test::Bencher;
pub use testvec::{get_dflt_vecs, get_vecs, TestVector};

/// Test hash function
pub fn test_hash<G>(tests: Vec<TestVector>, ciphersuite: &[u8], len: usize) -> Result<()>
where
    G: CurveProjective + HashToCurve<ExpandMsgXmd<Sha256>> + SerDes,
{
    for TestVector { msg, expect, .. } in tests {
        let result = G::hash_to_curve(&msg, ciphersuite);
        match expect {
            None => println!("{:?}", result),
            Some(e) => {
                let mut buf = [0u8; 96];
                {
                    let mut cur = Cursor::new(&mut buf[..]);
                    result.serialize(&mut cur, true)?;
                }
                assert_eq!(e.as_ref() as &[u8], &buf[..len]);

                let deser = G::deserialize(&mut Cursor::new(&e), true)?;
                assert_eq!(result, deser);
            }
        }
    }
    Ok(())
}

/// Benchmark the hash function
pub fn bench_hash<G>(b: &mut Bencher, tests: Vec<TestVector>, ciphersuite: &[u8])
where
    G: CurveProjective + HashToCurve<ExpandMsgXmd<Sha256>>,
{
    for TestVector { msg, .. } in tests {
        b.iter(|| {
            testbench::black_box(G::hash_to_curve(&msg, ciphersuite));
        })
    }
}

/// Test sign functionality for Basic
pub fn test_sig_basic<G>(tests: Vec<TestVector>, len: usize) -> Result<()>
where
    G: BLSSignatureBasic<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    for TestVector { msg, sk, expect } in tests {
        let (x_prime, pk) = G::keygen(sk);
        let sig = G::sign(x_prime, &msg);
        assert!(G::verify(pk, sig, &msg));
        match expect {
            None => println!("{:?}", sig),
            Some(e) => {
                let mut buf = [0u8; 96];
                {
                    let mut cur = Cursor::new(&mut buf[..]);
                    sig.serialize(&mut cur, true)?;
                }
                assert_eq!(e.as_ref() as &[u8], &buf[..len]);

                let deser = G::deserialize(&mut Cursor::new(&e), true)?;
                assert_eq!(sig, deser);
            }
        }
    }
    Ok(())
}

/// Benchmark signing in the basic scheme function
pub fn bench_sig_basic_sign<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignatureBasic<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    for TestVector { msg, sk, .. } in tests {
        let (x_prime, _) = G::keygen(sk);
        b.iter(|| {
            testbench::black_box(G::sign(x_prime, &msg));
        })
    }
}

/// Benchmark verification in the basic scheme
pub fn bench_sig_basic_verify<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignatureBasic<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    for TestVector { msg, sk, .. } in tests {
        let (x_prime, pk) = G::keygen(sk);
        let sig = G::sign(x_prime, &msg);
        b.iter(|| {
            testbench::black_box(G::verify(pk, sig, &msg));
        })
    }
}

/// Benchmark aggregation in the basic scheme function
pub fn bench_sig_basic_aggregate<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignatureBasic<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    let mut sigs = Vec::new();
    for TestVector { msg, sk, .. } in tests {
        let (x_prime, pk) = G::keygen(sk);
        let sig = G::sign(x_prime, &msg);
        sigs.push(sig);
    }
    b.iter(|| {
        testbench::black_box(G::aggregate(&sigs));
    })
}

/// Benchmark aggregation in the basic scheme function
pub fn bench_sig_basic_aggregate_verify<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignatureBasic<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    let mut sigs = Vec::new();
    let mut msgs = Vec::new();
    let mut pks = Vec::new();
    for TestVector { msg, sk, .. } in tests {
        let (x_prime, pk) = G::keygen(sk);
        let sig = G::sign(x_prime, &msg);
        sigs.push(sig);
        msgs.push(msg);
        pks.push(pk);
    }
    let aggregates = testbench::black_box(G::aggregate(&sigs));
    b.iter(|| testbench::black_box(G::aggregate_verify(&pks, &msgs, aggregates)))
}

/// Test sign functionality for Augmented
pub fn test_sig_aug<G>(tests: Vec<TestVector>, len: usize) -> Result<()>
where
    G: BLSSignatureAug<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    for TestVector { msg, sk, expect } in tests {
        let (x_prime, pk) = G::keygen(sk);
        let sig = G::sign(x_prime, &msg);
        assert!(G::verify(pk, sig, &msg));
        match expect {
            None => println!("{:?}", sig),
            Some(e) => {
                let mut buf = [0u8; 96];
                {
                    let mut cur = Cursor::new(&mut buf[..]);
                    sig.serialize(&mut cur, true)?;
                }
                assert_eq!(e.as_ref() as &[u8], &buf[..len]);

                let deser = G::deserialize(&mut Cursor::new(&e), true)?;
                assert_eq!(sig, deser);
            }
        }
    }
    Ok(())
}

/// Benchmark signing in the basic scheme function
pub fn bench_sig_aug_sign<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignatureAug<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    for TestVector { msg, sk, .. } in tests {
        let (x_prime, _) = G::keygen(sk);
        b.iter(|| {
            testbench::black_box(G::sign(x_prime, &msg));
        })
    }
}

/// Benchmark verification in the basic scheme
pub fn bench_sig_aug_verify<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignatureAug<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    for TestVector { msg, sk, .. } in tests {
        let (x_prime, pk) = G::keygen(sk);
        let sig = G::sign(x_prime, &msg);
        b.iter(|| {
            testbench::black_box(G::verify(pk, sig, &msg));
        })
    }
}

/// Benchmark aggregation in the basic scheme function
pub fn bench_sig_aug_aggregate<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignatureAug<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    let mut sigs = Vec::new();
    for TestVector { msg, sk, .. } in tests {
        let (x_prime, pk) = G::keygen(sk);
        let sig = G::sign(x_prime, &msg);
        sigs.push(sig);
    }
    b.iter(|| {
        testbench::black_box(G::aggregate(&sigs));
    })
}

/// Benchmark aggregate verification in the aug scheme
pub fn bench_sig_aug_aggregate_verify<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignatureAug<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    let mut sigs = Vec::new();
    let mut msgs = Vec::new();
    let mut pks = Vec::new();
    for TestVector { msg, sk, .. } in tests {
        let (x_prime, pk) = G::keygen(sk);
        let sig = G::sign(x_prime, &msg);
        sigs.push(sig);
        msgs.push(msg);
        pks.push(pk);
    }
    let aggregates = testbench::black_box(G::aggregate(&sigs));
    b.iter(|| testbench::black_box(G::aggregate_verify(&pks, &msgs, aggregates)))
}

/// Test sign functionality for Pop
pub fn test_sig_pop<G>(tests: Vec<TestVector>, len: usize) -> Result<()>
where
    G: BLSSignaturePop<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    for TestVector { msg, sk, expect } in tests {
        let (x_prime, pk) = G::keygen(sk);
        let sig = G::sign(x_prime, &msg);
        assert!(G::verify(pk, sig, &msg));
        match expect {
            None => println!("{:?}", sig),
            Some(e) => {
                let mut buf = [0u8; 96];
                {
                    let mut cur = Cursor::new(&mut buf[..]);
                    sig.serialize(&mut cur, true)?;
                }
                assert_eq!(e.as_ref() as &[u8], &buf[..len]);

                let deser = G::deserialize(&mut Cursor::new(&e), true)?;
                assert_eq!(sig, deser);
            }
        }
    }
    Ok(())
}

/// Test sign functionality for Pop
pub fn test_pop<G>(tests: Vec<TestVector>, len: usize) -> Result<()>
where
    G: BLSSignaturePop<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    for TestVector { sk, expect, .. } in tests {
        let (_, pk) = G::keygen(&sk[..]);
        let sig = G::pop_prove(&sk[..]);
        assert!(G::pop_verify(pk, sig));
        match expect {
            None => println!("{:?}", sig),
            Some(e) => {
                let mut buf = [0u8; 96];
                {
                    let mut cur = Cursor::new(&mut buf[..]);
                    sig.serialize(&mut cur, true)?;
                }
                assert_eq!(e.as_ref() as &[u8], &buf[..len]);

                let deser = G::deserialize(&mut Cursor::new(&e), true)?;
                assert_eq!(sig, deser);
            }
        }
    }
    Ok(())
}

/// Benchmark signing in the basic scheme function
pub fn bench_sig_pop_sign<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignaturePop<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    for TestVector { msg, sk, .. } in tests {
        let (x_prime, _) = G::keygen(sk);
        b.iter(|| {
            testbench::black_box(G::sign(x_prime, &msg));
        })
    }
}

/// Benchmark verification in the basic scheme
pub fn bench_sig_pop_verify<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignaturePop<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    for TestVector { msg, sk, .. } in tests {
        let (x_prime, pk) = G::keygen(sk);
        let sig = G::sign(x_prime, &msg);
        b.iter(|| {
            testbench::black_box(G::pop_verify(pk, sig));
        })
    }
}

/// Benchmark aggregation in the basic scheme function
pub fn bench_sig_pop_aggregate<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignaturePop<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    let mut sigs = Vec::new();
    for TestVector { msg, sk, .. } in tests {
        let (x_prime, pk) = G::keygen(sk);
        let sig = G::sign(x_prime, &msg);
        sigs.push(sig);
    }
    b.iter(|| {
        testbench::black_box(G::aggregate(&sigs));
    })
}

/// Benchmark aggregation in the basic scheme function
pub fn bench_sig_pop_aggregate_verify<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignaturePop<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    let mut sigs = Vec::new();
    let mut msgs = Vec::new();
    let mut pks = Vec::new();
    for TestVector { msg, sk, .. } in tests {
        let (x_prime, pk) = G::keygen(sk);
        let sig = G::sign(x_prime, &msg);
        sigs.push(sig);
        msgs.push(msg);
        pks.push(pk);
    }
    let aggregates = testbench::black_box(G::aggregate(&sigs));
    b.iter(|| testbench::black_box(G::aggregate_verify(&pks, &msgs, aggregates)))
}

/// Benchmark aggregation in the basic scheme function
pub fn bench_sig_pop_multisig_verify<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignaturePop<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    let mut viter = tests.into_iter();
    let ftest = viter.nth(0).unwrap();

    let mut sigs = Vec::new();
    let mut pks = Vec::new();

    for TestVector { msg, sk, .. } in viter {
        let (x_prime, pk) = G::keygen(sk);
        let sig = G::sign(x_prime, &ftest.msg);
        sigs.push(sig);
        pks.push(pk);
    }
    let aggregates = testbench::black_box(G::aggregate(&sigs));
    b.iter(|| testbench::black_box(G::multisig_verify(&pks, aggregates, &ftest.msg)))
}

/// Benchmark the  Signature function
pub fn bench_sig_pop_prove<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignaturePop<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    for TestVector { sk, .. } in tests {
        b.iter(|| testbench::black_box(G::pop_prove(&sk[..])));
    }
}

/// Benchmark the  Signature function
pub fn bench_sig_pop_pop_verify<G>(b: &mut Bencher, tests: Vec<TestVector>)
where
    G: BLSSignaturePop<ExpandMsgXmd<Sha256>> + CurveProjective + SerDes,
{
    for TestVector { sk, .. } in tests {
        let proof = G::pop_prove(&sk[..]);
        let (x_prime, pk) = G::keygen(sk);
        b.iter(|| testbench::black_box(G::pop_verify(pk, proof)));
    }
}
