use super::get_dflt_vecs;
use super::*;
use pairing_plus::bls12_381::{G1, G2};

extern crate test;
use self::test::bench::Bencher;

#[bench]
fn bench_get_dflt_vecs(b: &mut Bencher) {
    b.iter(|| {
        test::black_box(
            get_dflt_vecs("hash_g1")
                .unwrap()
                .map(|x| x.unwrap())
                .collect::<Vec<Vec<TestVector>>>(),
        )
    })
}

//
// #[bench]
// fn bench_hash_g1(b: &mut Bencher) {
//     for vec in get_dflt_vecs("hash_g1").unwrap() {
//         bench_hash::<G1>(b, vec.unwrap(), &[1u8]);
//     }
// }
//
// #[bench]
// fn bench_hash_g2(b: &mut Bencher) {
//     for vec in get_dflt_vecs("hash_g2").unwrap() {
//         bench_hash::<G2>(b, vec.unwrap(), &[1u8]);
//     }
// }
//
// #[bench]
// fn bench_basic_sign_g1(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g1_basic").unwrap() {
//         bench_sig_basic_sign::<G1>(b, vec.unwrap());
//     }
// }
//
// #[bench]
// fn bench_basic_sign_g2(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g2_basic").unwrap() {
//         bench_sig_basic_sign::<G2>(b, vec.unwrap());
//     }
// }
//
// #[bench]
// fn bench_basic_verify_g1(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g1_basic").unwrap() {
//         bench_sig_basic_verify::<G1>(b, vec.unwrap());
//     }
// }
//
// #[bench]
// fn bench_basic_verify_g2(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g2_basic").unwrap() {
//         bench_sig_basic_verify::<G2>(b, vec.unwrap());
//     }
// }
//
// #[bench]
// fn bench_basic_aggregate_g1(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g1_basic").unwrap() {
//         bench_sig_basic_aggregate::<G1>(b, vec.unwrap());
//     }
// }
//
//
// #[bench]
// fn bench_basic_aggregate_g2(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g2_basic").unwrap() {
//         bench_sig_basic_aggregate::<G2>(b, vec.unwrap());
//     }
// }
//
//
// #[bench]
// fn bench_basic_aggregate_verify_g1(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g1_basic").unwrap() {
//         bench_sig_basic_aggregate_verify::<G1>(b, vec.unwrap());
//     }
// }
//
//
// #[bench]
// fn bench_basic_aggregate_verify_g2(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g2_basic").unwrap() {
//         bench_sig_basic_aggregate_verify::<G2>(b, vec.unwrap());
//     }
// }
//
//
// #[bench]
// fn bench_aug_sign_g1(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g1_aug").unwrap() {
//         bench_sig_aug_sign::<G1>(b, vec.unwrap());
//     }
// }
//
// #[bench]
// fn bench_aug_sign_g2(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g2_aug").unwrap() {
//         bench_sig_aug_sign::<G2>(b, vec.unwrap());
//     }
// }
//
// #[bench]
// fn bench_aug_verify_g1(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g1_aug").unwrap() {
//         bench_sig_aug_verify::<G1>(b, vec.unwrap());
//     }
// }
//
// #[bench]
// fn bench_aug_verify_g2(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g2_aug").unwrap() {
//         bench_sig_aug_verify::<G2>(b, vec.unwrap());
//     }
// }
//
// #[bench]
// fn bench_aug_aggregate_g1(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g1_aug").unwrap() {
//         bench_sig_aug_aggregate::<G1>(b, vec.unwrap());
//     }
// }
//
//
// #[bench]
// fn bench_aug_aggregate_g2(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g2_aug").unwrap() {
//         bench_sig_aug_aggregate::<G2>(b, vec.unwrap());
//     }
// }
//
//
// #[bench]
// fn bench_aug_aggregate_verify_g1(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g1_aug").unwrap() {
//         bench_sig_aug_aggregate_verify::<G1>(b, vec.unwrap());
//     }
// }
//
//
// #[bench]
// fn bench_aug_aggregate_verify_g2(b: &mut Bencher) {
//     for vec in get_dflt_vecs("sig_g2_aug").unwrap() {
//         bench_sig_aug_aggregate_verify::<G2>(b, vec.unwrap());
//     }
// }

#[bench]
fn bench_pop_sign_g1(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g1_pop").unwrap() {
        bench_sig_pop_sign::<G1>(b, vec.unwrap());
    }
}

#[bench]
fn bench_pop_sign_g2(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g2_pop").unwrap() {
        bench_sig_pop_sign::<G2>(b, vec.unwrap());
    }
}

#[bench]
fn bench_pop_verify_g1(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g1_pop").unwrap() {
        bench_sig_pop_verify::<G1>(b, vec.unwrap());
    }
}

#[bench]
fn bench_pop_verify_g2(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g2_pop").unwrap() {
        bench_sig_pop_verify::<G2>(b, vec.unwrap());
    }
}

#[bench]
fn bench_pop_aggregate_g1(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g1_pop").unwrap() {
        bench_sig_pop_aggregate::<G1>(b, vec.unwrap());
    }
}


#[bench]
fn bench_pop_aggregate_g2(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g2_pop").unwrap() {
        bench_sig_pop_aggregate::<G2>(b, vec.unwrap());
    }
}


#[bench]
fn bench_pop_aggregate_verify_g1(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g1_pop").unwrap() {
        bench_sig_pop_aggregate_verify::<G1>(b, vec.unwrap());
    }
}


#[bench]
fn bench_pop_aggregate_verify_g2(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g2_pop").unwrap() {
        bench_sig_pop_aggregate_verify::<G2>(b, vec.unwrap());
    }
}

#[bench]
fn bench_pop_multisig_verify_g1(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g1_pop").unwrap() {
        bench_sig_pop_multisig_verify::<G1>(b, vec.unwrap());
    }
}


#[bench]
fn bench_pop_multisig_verify_g2(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g2_pop").unwrap() {
        bench_sig_pop_multisig_verify::<G2>(b, vec.unwrap());
    }
}


#[bench]
fn bench_pop_pop_verify_g1(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g1_pop").unwrap() {
        bench_sig_pop_pop_verify::<G1>(b, vec.unwrap());
    }
}


#[bench]
fn bench_pop_pop_verify_g2(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g2_pop").unwrap() {
        bench_sig_pop_pop_verify::<G2>(b, vec.unwrap());
    }
}

#[bench]
fn bench_pop_pop_prove_g1(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g1_pop").unwrap() {
        bench_sig_pop_prove::<G1>(b, vec.unwrap());
    }
}


#[bench]
fn bench_pop_pop_prove_g2(b: &mut Bencher) {
    for vec in get_dflt_vecs("sig_g2_pop").unwrap() {
        bench_sig_pop_prove::<G2>(b, vec.unwrap());
    }
}

