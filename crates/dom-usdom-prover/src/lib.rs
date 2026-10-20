//! Offline Groth16 proving boundary for native USDOM wallet spends.
//!
//! This crate is deliberately absent from the node dependency graph. It parses
//! an externally produced ceremony key, binds its embedded verifying key to the
//! bridge-committed verifier configuration, creates one randomized proof, and
//! verifies the result before returning bytes. It contains no setup API and no
//! embedded proving key.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use dom_core::Hash256;
use dom_crypto::hash::blake2b_256_tagged;
use dom_usdom_privacy::{circuit::SpendCircuit, privacy_policy_hash, verifier::SpendVerifier};
use rand::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroize;

const PROVING_KEY_ID_TAG: &str = "DOM:usdom-spend-proving-key:v1";
const MAX_PROVING_KEY_BYTES: usize = 64 * 1024 * 1024;

fn proving_key_has_frozen_circuit_shape(proving_key: &ProvingKey<Bn254>) -> bool {
    let constraints = ConstraintSystem::new_ref();
    constraints.set_mode(SynthesisMode::Setup);
    constraints.set_optimization_goal(OptimizationGoal::Constraints);
    if SpendCircuit::default()
        .generate_constraints(constraints.clone())
        .is_err()
    {
        return false;
    }
    constraints.finalize();
    let instance_variables = constraints.num_instance_variables();
    let witness_variables = constraints.num_witness_variables();
    let Some(domain) =
        GeneralEvaluationDomain::<Fr>::new(constraints.num_constraints() + instance_variables)
    else {
        return false;
    };
    let assignments = instance_variables + witness_variables;
    proving_key.a_query.len() == assignments
        && proving_key.b_g1_query.len() == assignments
        && proving_key.b_g2_query.len() == assignments
        && proving_key.l_query.len() == witness_variables
        && proving_key.h_query.len() == domain.size() - 1
}

/// Failure while loading a ceremony key or producing a self-verified proof.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProverError {
    /// Proving-key bytes are missing, oversized, malformed, or noncanonical.
    #[error("invalid canonical USDOM proving key")]
    InvalidProvingKey,
    /// The proving key embeds a verifier with the wrong public-input shape.
    #[error("USDOM proving key embeds an invalid spend verifier")]
    InvalidEmbeddedVerifier,
    /// The embedded verifier does not match the bridge-committed config hash.
    #[error("USDOM proving key does not match the expected verifier configuration")]
    VerifierConfigMismatch,
    /// Groth16 could not construct a proof from the supplied witness.
    #[error("USDOM spend proof construction failed")]
    ProofConstructionFailed,
    /// The supplied private witness does not satisfy the public statement.
    #[error("USDOM spend witness does not satisfy the public statement")]
    UnsatisfiedWitness,
    /// The newly generated proof failed the embedded verifier and is withheld.
    #[error("USDOM generated proof failed mandatory self-verification")]
    SelfVerificationFailed,
}

/// Parsed immutable ceremony proving key plus its exact verifier identity.
pub struct SpendProver {
    proving_key: ProvingKey<Bn254>,
    verifier: SpendVerifier,
    proving_key_id: Hash256,
}

impl SpendProver {
    /// Parse one canonical compressed proving key and require that its embedded
    /// verifying key has the exact bridge-committed configuration hash.
    pub fn from_bytes(
        bytes: &[u8],
        expected_verifier_config_hash: Hash256,
    ) -> Result<Self, ProverError> {
        if bytes.is_empty() || bytes.len() > MAX_PROVING_KEY_BYTES {
            return Err(ProverError::InvalidProvingKey);
        }
        let mut reader = bytes;
        let proving_key = ProvingKey::<Bn254>::deserialize_compressed(&mut reader)
            .map_err(|_| ProverError::InvalidProvingKey)?;
        if !reader.is_empty() {
            return Err(ProverError::InvalidProvingKey);
        }
        if !proving_key_has_frozen_circuit_shape(&proving_key) {
            return Err(ProverError::InvalidProvingKey);
        }
        let mut canonical = Vec::new();
        proving_key
            .serialize_compressed(&mut canonical)
            .map_err(|_| ProverError::InvalidProvingKey)?;
        if canonical != bytes {
            return Err(ProverError::InvalidProvingKey);
        }
        let mut verifying_key = Vec::new();
        proving_key
            .vk
            .serialize_compressed(&mut verifying_key)
            .map_err(|_| ProverError::InvalidEmbeddedVerifier)?;
        let verifier = SpendVerifier::from_bytes(&verifying_key)
            .map_err(|_| ProverError::InvalidEmbeddedVerifier)?;
        if verifier.config_hash() != expected_verifier_config_hash {
            return Err(ProverError::VerifierConfigMismatch);
        }
        let mut identity = Vec::with_capacity(32 + canonical.len());
        identity.extend_from_slice(privacy_policy_hash().as_bytes());
        identity.extend_from_slice(&canonical);
        Ok(Self {
            proving_key,
            verifier,
            proving_key_id: blake2b_256_tagged(PROVING_KEY_ID_TAG, &identity),
        })
    }

    /// Domain-separated identity of the exact canonical proving-key bytes.
    pub fn proving_key_id(&self) -> Hash256 {
        self.proving_key_id
    }

    /// Bridge-committed identity of the embedded verifying key and policy.
    pub fn verifier_config_hash(&self) -> Hash256 {
        self.verifier.config_hash()
    }

    /// Produce one randomized canonical proof and withhold it unless the
    /// embedded verifier accepts every public field in `circuit.statement`.
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        circuit: SpendCircuit,
        rng: &mut R,
    ) -> Result<Vec<u8>, ProverError> {
        // ark-groth16 asserts on an unsatisfied constraint system. Check the
        // exact circuit first so malformed wallet data cannot panic the caller.
        let constraints = ConstraintSystem::new_ref();
        circuit
            .clone()
            .generate_constraints(constraints.clone())
            .map_err(|_| ProverError::ProofConstructionFailed)?;
        let satisfaction = constraints.is_satisfied();
        if let Some(mut inner) = constraints.borrow_mut() {
            inner.witness_assignment.zeroize();
        }
        if !satisfaction.map_err(|_| ProverError::ProofConstructionFailed)? {
            return Err(ProverError::UnsatisfiedWitness);
        }
        let statement = circuit.statement;
        let proof =
            Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &self.proving_key, rng)
                .map_err(|_| ProverError::ProofConstructionFailed)?;
        let mut bytes = Vec::new();
        proof
            .serialize_compressed(&mut bytes)
            .map_err(|_| ProverError::ProofConstructionFailed)?;
        self.verifier
            .verify(statement, &bytes)
            .map_err(|_| ProverError::SelfVerificationFailed)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use dom_usdom_privacy::{
        chain_scalar,
        circuit::{InputWitness, OutputWitness, SpendStatement},
        empty_subtree_roots, owner_commitment, privacy_policy_hash, IncrementalNoteTree,
        NoteOpening, Scalar, NOTE_ORIGIN_ISSUANCE, NOTE_ORIGIN_PRIVATE, NOTE_TREE_DEPTH,
    };
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    fn scalar(value: u64) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Scalar::from_bytes(bytes).unwrap()
    }

    fn valid_burn_circuit() -> SpendCircuit {
        let chain = chain_scalar([0x11; 32], *privacy_policy_hash().as_bytes());
        let secret = scalar(7);
        let input_note = NoteOpening {
            chain,
            origin: NOTE_ORIGIN_ISSUANCE,
            value: 10,
            owner: owner_commitment(chain, secret).unwrap(),
            rho: scalar(8),
        };
        let input_commitment = input_note.commitment().unwrap();
        let mut tree = IncrementalNoteTree::new();
        assert_eq!(tree.append(input_commitment).unwrap(), 0);
        let output = OutputWitness {
            enabled: true,
            value: 7,
            owner: scalar(9),
            rho: scalar(10),
        };
        let output_commitment = NoteOpening {
            chain,
            origin: NOTE_ORIGIN_PRIVATE,
            value: output.value,
            owner: output.owner,
            rho: output.rho,
        }
        .commitment()
        .unwrap();
        SpendCircuit {
            statement: SpendStatement {
                chain,
                anchor: tree.root(),
                nullifiers: [input_note.nullifier(secret).unwrap(), Scalar::ZERO],
                output_notes: [output_commitment, Scalar::ZERO],
                burn_amount: 3,
                effect: scalar(11),
                memo: scalar(12),
            },
            inputs: [
                InputWitness {
                    enabled: true,
                    origin: input_note.origin,
                    value: input_note.value,
                    owner_secret: secret,
                    rho: input_note.rho,
                    leaf_index: 0,
                    siblings: empty_subtree_roots()[..NOTE_TREE_DEPTH].try_into().unwrap(),
                },
                InputWitness::default(),
            ],
            outputs: [output, OutputWitness::default()],
        }
    }

    #[test]
    fn external_key_is_canonical_bound_and_every_returned_proof_self_verifies() {
        // Deterministic single-party setup exists only inside this test. Its
        // bytes are never exported and are categorically unsafe for funds.
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_5052);
        let circuit = valid_burn_circuit();
        let parameters =
            Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
                .unwrap();
        let mut proving_key_bytes = Vec::new();
        parameters
            .serialize_compressed(&mut proving_key_bytes)
            .unwrap();
        assert!(proving_key_bytes.len() < MAX_PROVING_KEY_BYTES);
        let mut verifying_key_bytes = Vec::new();
        parameters
            .vk
            .serialize_compressed(&mut verifying_key_bytes)
            .unwrap();
        let verifier = SpendVerifier::from_bytes(&verifying_key_bytes).unwrap();
        let prover = SpendProver::from_bytes(&proving_key_bytes, verifier.config_hash()).unwrap();
        assert_eq!(prover.verifier_config_hash(), verifier.config_hash());
        assert_ne!(prover.proving_key_id(), Hash256::ZERO);

        let proof = prover.prove(circuit.clone(), &mut rng).unwrap();
        verifier.verify(circuit.statement, &proof).unwrap();

        let mut wrong_hash = verifier.config_hash();
        let mut wrong = *wrong_hash.as_bytes();
        wrong[0] ^= 1;
        wrong_hash = Hash256::from_bytes(wrong);
        assert!(matches!(
            SpendProver::from_bytes(&proving_key_bytes, wrong_hash),
            Err(ProverError::VerifierConfigMismatch)
        ));
        let mut trailing = proving_key_bytes.clone();
        trailing.push(0);
        assert!(matches!(
            SpendProver::from_bytes(&trailing, verifier.config_hash()),
            Err(ProverError::InvalidProvingKey)
        ));
        let mut truncated_parameters = parameters;
        truncated_parameters.a_query.clear();
        let mut truncated = Vec::new();
        truncated_parameters
            .serialize_compressed(&mut truncated)
            .unwrap();
        assert!(matches!(
            SpendProver::from_bytes(&truncated, verifier.config_hash()),
            Err(ProverError::InvalidProvingKey)
        ));

        let mut unsatisfied = circuit;
        unsatisfied.statement.burn_amount += 1;
        assert!(matches!(
            prover.prove(unsatisfied, &mut rng),
            Err(ProverError::UnsatisfiedWitness)
        ));
    }
}
