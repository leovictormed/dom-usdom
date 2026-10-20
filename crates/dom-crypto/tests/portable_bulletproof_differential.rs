//! Differential checks between the live C backend and the portable zkVM path.

use dom_bulletproof_portable::verify_bounded_range_proof;
use dom_crypto::pedersen::BlindingFactor;
use dom_crypto::{
    bp2_prove_with_nonce, bp2_verify, range_proof_prove_bytes_with_extra_commit,
    range_proof_verify_with_extra_commit, MAX_PROVABLE_VALUE,
};

#[test]
fn portable_verifier_accepts_native_frozen_shape() {
    for (value, blind_byte, nonce_byte) in [
        (0, 0x11, 0xa1),
        (42_424_242, 0x22, 0xa2),
        (MAX_PROVABLE_VALUE, 0x33, 0xa3),
    ] {
        let blinding = BlindingFactor::from_bytes([blind_byte; 32]).expect("valid blinding");
        let (proof, commitment) =
            bp2_prove_with_nonce(value, &blinding, &[nonce_byte; 32]).expect("native proof");
        assert!(bp2_verify(&commitment, &proof).expect("native verification"));
        assert!(
            verify_bounded_range_proof(&commitment, &proof, &[]).expect("portable verification")
        );

        for index in [0, 31, 64, 100, 192, 193, 352, 353, 738] {
            let mut corrupted = proof.clone();
            corrupted[index] ^= 1;
            let native = bp2_verify(&commitment, &corrupted).unwrap_or(false);
            let portable =
                verify_bounded_range_proof(&commitment, &corrupted, &[]).unwrap_or(false);
            assert_eq!(portable, native, "differential mismatch at byte {index}");
            assert!(!portable, "corrupted proof verified at byte {index}");
        }
    }
}

#[test]
fn portable_verifier_binds_extra_commit_identically() {
    let blinding = BlindingFactor::from_bytes([0x44; 32]).expect("valid blinding");
    let extra_commit = b"DOM:portable-bulletproof:differential:v1";
    let (proof, commitment) =
        range_proof_prove_bytes_with_extra_commit(7_654_321, &blinding, extra_commit)
            .expect("native proof");

    assert!(
        range_proof_verify_with_extra_commit(&commitment, &proof, extra_commit)
            .expect("native verification")
    );
    assert!(
        verify_bounded_range_proof(&commitment, &proof, extra_commit)
            .expect("portable verification")
    );

    let wrong = b"DOM:portable-bulletproof:differential:v2";
    assert_eq!(
        verify_bounded_range_proof(&commitment, &proof, wrong).unwrap_or(false),
        range_proof_verify_with_extra_commit(&commitment, &proof, wrong).unwrap_or(false)
    );
    assert!(!verify_bounded_range_proof(&commitment, &proof, wrong).unwrap_or(false));
    assert!(!verify_bounded_range_proof(&commitment, &proof, &[]).unwrap_or(false));
}
