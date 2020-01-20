#![feature(test)]
#![allow(non_snake_case)]
extern crate test;
extern crate curv;
extern crate bulletproof;

use test::Bencher;
use bulletproof::proofs::range_proof::{RangeProof, generate_random_point};
use curv::arithmetic::traits::{Converter, Samplable};
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::*;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use curv::elliptic::curves::traits::ECPoint;

#[bench]
fn bench_main(b: &mut Bencher) {
    // bit range
    let n = 64;
    // batch size
    let m = 1;
    let nm = n * m;
    // some seed for generating g and h vectors
    let KZen: &[u8] = &[75, 90, 101, 110];
    let kzen_label = BigInt::from(KZen);

    // G,H - points for pederson commitment: com  = vG + rH
    let G: GE = ECPoint::generator();
    let label = BigInt::from(1);
    let hash = HSha256::create_hash(&[&label]);
    let H = generate_random_point(&Converter::to_vec(&hash));

    let g_vec = (0..nm)
        .map(|i| {
            let kzen_label_i = BigInt::from(i as u32) + &kzen_label;
            let hash_i = HSha256::create_hash(&[&kzen_label_i]);
            generate_random_point(&Converter::to_vec(&hash_i))
        })
        .collect::<Vec<GE>>();

    // can run in parallel to g_vec:
    let h_vec = (0..nm)
        .map(|i| {
            let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + &kzen_label;
            let hash_j = HSha256::create_hash(&[&kzen_label_j]);
            generate_random_point(&Converter::to_vec(&hash_j))
        })
        .collect::<Vec<GE>>();

    let range = BigInt::from(2).pow(n as u32);
    let v_vec = (0..m)
        .map(|_| ECScalar::from(&BigInt::sample_below(&range)))
        .collect::<Vec<FE>>();

    let r_vec = (0..m).map(|_| ECScalar::new_random()).collect::<Vec<FE>>();

    let ped_com_vec = (0..m)
        .map(|i| {
            let ped_com = &G * &v_vec[i] + &H * &r_vec[i];
            ped_com
        })
        .collect::<Vec<GE>>();

    let range_proof = RangeProof::prove(&g_vec, &h_vec, &G, &H, v_vec, &r_vec, n);
//    let result = RangeProof::verify(&range_proof, &g_vec, &h_vec, &G, &H, &ped_com_vec, n);
    b.iter(|| RangeProof::verify(&range_proof, &g_vec, &h_vec, &G, &H, &ped_com_vec, n));
}