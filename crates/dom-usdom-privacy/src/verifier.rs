//! Canonical Groth16 verification boundary for the frozen spend circuit.
//!
//! This module has no setup or proving API. Production must obtain a verifying
//! key from a separately governed ceremony, audit it, and commit the returned
//! configuration hash in the native bridge identity.

use ark_bn254::Bn254;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dom_core::blake2b_256_tagged;
use dom_core::Hash256;
use thiserror::Error;

use crate::{circuit::SpendStatement, privacy_policy_hash};

const VERIFIER_CONFIG_TAG: &str = "DOM:usdom-spend-verifier-config:v1";
const GROTH16_PROOF_BYTES: usize = 128;
const MAX_VERIFYING_KEY_BYTES: usize = 4 * 1024;
const PUBLIC_INPUTS: usize = 9;

/// Failure while decoding or applying the native USDOM spend verifier.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerifierError {
    /// Verifying-key bytes are missing, oversized, malformed, or noncanonical.
    #[error("invalid canonical USDOM verifying key")]
    InvalidVerifyingKey,
    /// The key does not expose the exact frozen public-input count.
    #[error("USDOM verifying key has the wrong public-input shape")]
    WrongPublicInputShape,
    /// Proof bytes are malformed or noncanonical.
    #[error("invalid canonical USDOM spend proof")]
    InvalidProofEncoding,
    /// The proof does not authenticate the supplied public statement.
    #[error("USDOM spend proof verification failed")]
    VerificationFailed,
}

/// Parsed immutable verifier plus its bridge-committed configuration hash.
pub struct SpendVerifier {
    prepared: PreparedVerifyingKey<Bn254>,
    config_hash: Hash256,
}

impl SpendVerifier {
    /// Parse one unique compressed BN254 verifying key and freeze its identity.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, VerifierError> {
        if bytes.is_empty() || bytes.len() > MAX_VERIFYING_KEY_BYTES {
            return Err(VerifierError::InvalidVerifyingKey);
        }
        let mut reader = bytes;
        let key = VerifyingKey::<Bn254>::deserialize_compressed(&mut reader)
            .map_err(|_| VerifierError::InvalidVerifyingKey)?;
        if !reader.is_empty() {
            return Err(VerifierError::InvalidVerifyingKey);
        }
        let mut canonical = Vec::new();
        key.serialize_compressed(&mut canonical)
            .map_err(|_| VerifierError::InvalidVerifyingKey)?;
        if canonical != bytes {
            return Err(VerifierError::InvalidVerifyingKey);
        }
        if key.gamma_abc_g1.len() != PUBLIC_INPUTS + 1 {
            return Err(VerifierError::WrongPublicInputShape);
        }
        let mut identity = Vec::with_capacity(32 + canonical.len());
        identity.extend_from_slice(privacy_policy_hash().as_bytes());
        identity.extend_from_slice(&canonical);
        Ok(Self {
            prepared: prepare_verifying_key(&key),
            config_hash: blake2b_256_tagged(VERIFIER_CONFIG_TAG, &identity),
        })
    }

    /// Domain-separated commitment to the primitive policy and exact key.
    pub fn config_hash(&self) -> Hash256 {
        self.config_hash
    }

    /// Verify one canonical proof against every direct public statement field.
    pub fn verify(
        &self,
        statement: SpendStatement,
        proof_bytes: &[u8],
    ) -> Result<(), VerifierError> {
        if proof_bytes.len() != GROTH16_PROOF_BYTES {
            return Err(VerifierError::InvalidProofEncoding);
        }
        let mut reader = proof_bytes;
        let proof = Proof::<Bn254>::deserialize_compressed(&mut reader)
            .map_err(|_| VerifierError::InvalidProofEncoding)?;
        if !reader.is_empty() {
            return Err(VerifierError::InvalidProofEncoding);
        }
        let mut canonical = Vec::with_capacity(GROTH16_PROOF_BYTES);
        proof
            .serialize_compressed(&mut canonical)
            .map_err(|_| VerifierError::InvalidProofEncoding)?;
        if canonical.as_slice() != proof_bytes {
            return Err(VerifierError::InvalidProofEncoding);
        }
        if !Groth16::<Bn254>::verify_proof(&self.prepared, &proof, &statement.public_inputs())
            .map_err(|_| VerifierError::VerificationFailed)?
        {
            return Err(VerifierError::VerificationFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    #[test]
    fn malformed_keys_and_proofs_fail_closed() {
        assert!(matches!(
            SpendVerifier::from_bytes(&[]),
            Err(VerifierError::InvalidVerifyingKey)
        ));
        assert!(matches!(
            SpendVerifier::from_bytes(&vec![0u8; MAX_VERIFYING_KEY_BYTES + 1]),
            Err(VerifierError::InvalidVerifyingKey)
        ));
    }

    #[test]
    fn test_only_setup_proves_the_frozen_shape_and_binds_every_public_input() {
        // Deterministic single-party setup is confined to this unit test and
        // must never be exported or used with funds.
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5445);
        let circuit = crate::circuit::tests_support::valid_burn_circuit();
        let parameters =
            Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
                .unwrap();
        let mut key_bytes = Vec::new();
        parameters.vk.serialize_compressed(&mut key_bytes).unwrap();
        let verifier = SpendVerifier::from_bytes(&key_bytes).unwrap();
        let proof = Groth16::<Bn254>::create_random_proof_with_reduction(
            circuit.clone(),
            &parameters,
            &mut rng,
        )
        .unwrap();
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        verifier.verify(circuit.statement, &proof_bytes).unwrap();

        for index in 0..PUBLIC_INPUTS {
            let mut changed = circuit.statement;
            let mut one = [0u8; 32];
            one[31] = 1;
            match index {
                0 => changed.chain = crate::Scalar::ZERO,
                1 => changed.anchor = crate::Scalar::ZERO,
                2 => changed.nullifiers[0] = crate::Scalar::ZERO,
                3 => changed.nullifiers[1] = crate::Scalar::from_bytes(one).unwrap(),
                4 => changed.output_notes[0] = crate::Scalar::ZERO,
                5 => changed.output_notes[1] = crate::Scalar::from_bytes(one).unwrap(),
                6 => changed.burn_amount += 1,
                7 => changed.effect = crate::Scalar::ZERO,
                8 => changed.memo = crate::Scalar::ZERO,
                _ => unreachable!(),
            }
            assert_eq!(
                verifier.verify(changed, &proof_bytes),
                Err(VerifierError::VerificationFailed),
                "public input {index}"
            );
        }
        proof_bytes[0] ^= 1;
        assert!(verifier.verify(circuit.statement, &proof_bytes).is_err());
    }
}
