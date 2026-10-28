//! Algebraic phase-2 contributions for the frozen BN254 Groth16 proving key.
//!
//! Each participant independently rescales `delta`; all delta-denominated
//! queries are inversely rescaled. Pairing equations prove that the new key is
//! one consistent, nontrivial transform of the preceding key without exposing
//! the participant scalar.

use ark_bn254::{Bn254, Fr};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, One, PrimeField, UniformRand, Zero};
use ark_groth16::{prepare_verifying_key, Groth16, ProvingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

const MAX_PROVING_KEY_BYTES: usize = 64 * 1024 * 1024;
const MAX_VERIFYING_KEY_BYTES: usize = 4 * 1024;
const SERIALIZED_LENGTH_BYTES: usize = 8;
const PHASE2_PROOF_BYTES: usize = 32 + 64 + 32;

/// Failure to decode, contribute to, or algebraically verify a ceremony key.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CeremonyError {
    /// The proving key is absent, oversized, malformed, or noncanonical.
    #[error("invalid canonical Groth16 proving key")]
    InvalidProvingKey,
    /// The contribution is an identity transform or changes invariant data.
    #[error("invalid Groth16 phase-2 contribution structure")]
    InvalidContribution,
    /// A pairing equation disproves the claimed common rescaling.
    #[error("Groth16 phase-2 contribution algebraic verification failed")]
    AlgebraicVerificationFailed,
}

/// Public transcript binding for one Phase-2 delta contribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phase2Context {
    /// Frozen release commitment.
    pub release: [u8; 32],
    /// Exact circuit fingerprint.
    pub circuit: [u8; 32],
    /// Contributor identity commitment.
    pub contributor: [u8; 32],
    /// One-based contribution ordinal.
    pub ordinal: u64,
    /// Hash of the preceding social transcript record.
    pub previous_transcript: [u8; 32],
}

/// Schnorr/Chaum-Pedersen knowledge proof for the Phase-2 delta scalar.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase2KnowledgeProof {
    /// Nonce commitment in G1.
    pub commitment_g1: ark_bn254::G1Affine,
    /// Nonce commitment in G2.
    pub commitment_g2: ark_bn254::G2Affine,
    /// Fiat-Shamir response.
    pub response: Fr,
}

/// Canonical updated key and its Phase-2 knowledge proof.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase2Artifact {
    /// Canonical updated proving-key bytes.
    pub proving_key: Vec<u8>,
    /// Proof that the contributor knew the common delta rescaling.
    pub proof: Phase2KnowledgeProof,
}

fn decode(bytes: &[u8]) -> Result<ProvingKey<Bn254>, CeremonyError> {
    if bytes.is_empty() || bytes.len() > MAX_PROVING_KEY_BYTES {
        return Err(CeremonyError::InvalidProvingKey);
    }
    let mut reader = bytes;
    let key = ProvingKey::deserialize_with_mode(&mut reader, Compress::Yes, Validate::Yes)
        .map_err(|_| CeremonyError::InvalidProvingKey)?;
    if !reader.is_empty() {
        return Err(CeremonyError::InvalidProvingKey);
    }
    let mut canonical = Vec::new();
    key.serialize_compressed(&mut canonical)
        .map_err(|_| CeremonyError::InvalidProvingKey)?;
    if canonical != bytes {
        return Err(CeremonyError::InvalidProvingKey);
    }
    Ok(key)
}

fn encode(key: &ProvingKey<Bn254>) -> Result<Vec<u8>, CeremonyError> {
    let mut bytes = Vec::new();
    key.serialize_compressed(&mut bytes)
        .map_err(|_| CeremonyError::InvalidProvingKey)?;
    Ok(bytes)
}

#[cfg(test)]
pub(crate) fn encode_for_phase1_test(key: &ProvingKey<Bn254>) -> Result<Vec<u8>, CeremonyError> {
    encode(key)
}

fn has_structural_identity(key: &ProvingKey<Bn254>) -> bool {
    key.vk.alpha_g1.is_zero()
        || key.vk.beta_g2.is_zero()
        || key.vk.gamma_g2.is_zero()
        || key.vk.delta_g2.is_zero()
        || key.beta_g1.is_zero()
        || key.delta_g1.is_zero()
        || key.vk.gamma_abc_g1.iter().any(AffineRepr::is_zero)
}

/// Canonical R1CS identity committed by every production ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircuitFingerprint {
    /// SHA-256 over matrices, counts, FFT domain, protocol domains and Poseidon parameters.
    pub sha256: [u8; 32],
    /// Exact number of constraints.
    pub constraints: usize,
    /// Exact number of public variables including Arkworks' constant one.
    pub instance_variables: usize,
    /// Exact number of private witness variables.
    pub witness_variables: usize,
    /// Exact FFT evaluation-domain size used by Groth16 setup.
    pub domain_size: usize,
}

fn append_usize(digest: &mut Sha256, value: usize) {
    digest.update((value as u64).to_be_bytes());
}
fn append_matrix(digest: &mut Sha256, matrix: &[Vec<(Fr, usize)>]) -> Result<(), CeremonyError> {
    append_usize(digest, matrix.len());
    for row in matrix {
        append_usize(digest, row.len());
        for (coefficient, index) in row {
            append_usize(digest, *index);
            let mut encoded = Vec::new();
            coefficient
                .serialize_compressed(&mut encoded)
                .map_err(|_| CeremonyError::InvalidContribution)?;
            digest.update(encoded);
        }
    }
    Ok(())
}

/// Recompute the frozen circuit fingerprint directly in Arkworks setup mode.
pub fn circuit_fingerprint() -> Result<CircuitFingerprint, CeremonyError> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    crate::circuit::SpendCircuit::default()
        .generate_constraints(cs.clone())
        .map_err(|_| CeremonyError::InvalidContribution)?;
    cs.finalize();
    let matrices = cs.to_matrices().ok_or(CeremonyError::InvalidContribution)?;
    let domain = GeneralEvaluationDomain::<Fr>::new(
        matrices.num_constraints + matrices.num_instance_variables,
    )
    .ok_or(CeremonyError::InvalidContribution)?;
    let mut digest = Sha256::new();
    digest.update(b"DOM:usdom-spend-r1cs-fingerprint:v1");
    for value in [
        matrices.num_constraints,
        matrices.num_instance_variables,
        matrices.num_witness_variables,
        domain.size(),
    ] {
        append_usize(&mut digest, value);
    }
    for value in [
        super::OWNER_DOMAIN,
        super::NOTE_DOMAIN,
        super::NULLIFIER_DOMAIN,
        super::NODE_DOMAIN,
        super::CHAIN_DOMAIN,
        super::RHO_DOMAIN,
        super::EFFECT_DOMAIN,
        super::MEMO_DOMAIN,
    ] {
        digest.update(value.to_be_bytes());
    }
    let mut poseidon = Vec::new();
    super::poseidon_config()
        .serialize_compressed(&mut poseidon)
        .map_err(|_| CeremonyError::InvalidContribution)?;
    digest.update(poseidon);
    append_matrix(&mut digest, &matrices.a)?;
    append_matrix(&mut digest, &matrices.b)?;
    append_matrix(&mut digest, &matrices.c)?;
    Ok(CircuitFingerprint {
        sha256: digest.finalize().into(),
        constraints: matrices.num_constraints,
        instance_variables: matrices.num_instance_variables,
        witness_variables: matrices.num_witness_variables,
        domain_size: domain.size(),
    })
}

/// Apply one fresh, nonidentity phase-2 delta contribution.
pub fn contribute<R: RngCore + CryptoRng>(
    previous: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, CeremonyError> {
    let mut key = decode(previous)?;
    let mut scalar = loop {
        let mut candidate = Fr::rand(rng);
        if !candidate.is_zero() && !candidate.is_one() {
            break candidate;
        }
        candidate.zeroize();
    };
    let mut inverse = scalar.inverse().ok_or(CeremonyError::InvalidContribution)?;
    key.delta_g1 = key.delta_g1.mul_bigint(scalar.into_bigint()).into_affine();
    key.vk.delta_g2 = key
        .vk
        .delta_g2
        .mul_bigint(scalar.into_bigint())
        .into_affine();
    for point in key.h_query.iter_mut().chain(key.l_query.iter_mut()) {
        *point = point.mul_bigint(inverse.into_bigint()).into_affine();
    }
    scalar.zeroize();
    inverse.zeroize();
    let bytes = encode(&key)?;
    verify_contribution(previous, &bytes)?;
    Ok(bytes)
}

fn phase2_challenge(
    previous: &[u8],
    next: &[u8],
    context: &Phase2Context,
    proof: &Phase2KnowledgeProof,
) -> Result<Fr, CeremonyError> {
    if context.ordinal == 0
        || context.release == [0; 32]
        || context.circuit == [0; 32]
        || context.contributor == [0; 32]
    {
        return Err(CeremonyError::InvalidContribution);
    }
    let mut digest = Sha256::new();
    digest.update(b"DOM:usdom-groth16-phase2-pok:v1");
    digest.update(context.release);
    digest.update(context.circuit);
    digest.update(context.contributor);
    digest.update(context.ordinal.to_be_bytes());
    digest.update(context.previous_transcript);
    digest.update(previous);
    digest.update(next);
    let mut commitment = Vec::new();
    proof
        .commitment_g1
        .serialize_compressed(&mut commitment)
        .map_err(|_| CeremonyError::InvalidContribution)?;
    proof
        .commitment_g2
        .serialize_compressed(&mut commitment)
        .map_err(|_| CeremonyError::InvalidContribution)?;
    digest.update(&commitment);
    let mut challenge = Fr::from_be_bytes_mod_order(&digest.finalize());
    if challenge.is_zero() {
        challenge = Fr::one();
    }
    Ok(challenge)
}

/// Apply Phase 2 and prove knowledge of its common nontrivial delta scalar.
pub fn contribute_with_proof<R: RngCore + CryptoRng>(
    previous: &[u8],
    context: &Phase2Context,
    rng: &mut R,
) -> Result<Phase2Artifact, CeremonyError> {
    let old = decode(previous)?;
    let mut scalar = loop {
        let mut candidate = Fr::rand(rng);
        if !candidate.is_zero() && !candidate.is_one() {
            break candidate;
        }
        candidate.zeroize();
    };
    let mut key = old.clone();
    let mut inverse = scalar.inverse().ok_or(CeremonyError::InvalidContribution)?;
    key.delta_g1 = key.delta_g1.mul_bigint(scalar.into_bigint()).into_affine();
    key.vk.delta_g2 = key
        .vk
        .delta_g2
        .mul_bigint(scalar.into_bigint())
        .into_affine();
    for point in key.h_query.iter_mut().chain(key.l_query.iter_mut()) {
        *point = point.mul_bigint(inverse.into_bigint()).into_affine();
    }
    let next = encode(&key)?;
    let mut nonce = loop {
        let mut candidate = Fr::rand(rng);
        if !candidate.is_zero() {
            break candidate;
        }
        candidate.zeroize();
    };
    let mut proof = Phase2KnowledgeProof {
        commitment_g1: old.delta_g1.mul_bigint(nonce.into_bigint()).into_affine(),
        commitment_g2: old
            .vk
            .delta_g2
            .mul_bigint(nonce.into_bigint())
            .into_affine(),
        response: Fr::zero(),
    };
    let challenge = phase2_challenge(previous, &next, context, &proof)?;
    proof.response = nonce + challenge * scalar;
    scalar.zeroize();
    inverse.zeroize();
    nonce.zeroize();
    verify_contribution_with_proof(previous, &next, context, &proof)?;
    Ok(Phase2Artifact {
        proving_key: next,
        proof,
    })
}

/// Verify Phase-2 algebra and the contributor's transcript-bound knowledge proof.
pub fn verify_contribution_with_proof(
    previous: &[u8],
    next: &[u8],
    context: &Phase2Context,
    proof: &Phase2KnowledgeProof,
) -> Result<(), CeremonyError> {
    verify_contribution(previous, next)?;
    let old = decode(previous)?;
    let new = decode(next)?;
    let c = phase2_challenge(previous, next, context, proof)?;
    if old.delta_g1.mul_bigint(proof.response.into_bigint())
        != proof.commitment_g1.into_group() + new.delta_g1.mul_bigint(c.into_bigint())
        || old.vk.delta_g2.mul_bigint(proof.response.into_bigint())
            != proof.commitment_g2.into_group() + new.vk.delta_g2.mul_bigint(c.into_bigint())
    {
        return Err(CeremonyError::AlgebraicVerificationFailed);
    }
    Ok(())
}

/// Canonically encode a complete Phase-2 contribution artifact.
pub fn encode_phase2_artifact(value: &Phase2Artifact) -> Result<Vec<u8>, CeremonyError> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|_| CeremonyError::InvalidContribution)?;
    Ok(bytes)
}

/// Decode a bounded canonical Phase-2 artifact with subgroup validation.
pub fn decode_phase2_artifact(bytes: &[u8]) -> Result<Phase2Artifact, CeremonyError> {
    if bytes.is_empty() || bytes.len() > MAX_PROVING_KEY_BYTES + 4096 {
        return Err(CeremonyError::InvalidContribution);
    }
    // `Phase2Artifact` starts with a canonically serialized `Vec<u8>`. Check
    // its declared length before Arkworks can reserve attacker-selected
    // capacity. The remainder is the fixed-width checked knowledge proof.
    let encoded_length: [u8; SERIALIZED_LENGTH_BYTES] = bytes
        .get(..SERIALIZED_LENGTH_BYTES)
        .ok_or(CeremonyError::InvalidContribution)?
        .try_into()
        .map_err(|_| CeremonyError::InvalidContribution)?;
    let proving_key_length = usize::try_from(u64::from_le_bytes(encoded_length))
        .map_err(|_| CeremonyError::InvalidContribution)?;
    let expected = SERIALIZED_LENGTH_BYTES
        .checked_add(proving_key_length)
        .and_then(|value| value.checked_add(PHASE2_PROOF_BYTES))
        .ok_or(CeremonyError::InvalidContribution)?;
    if proving_key_length == 0
        || proving_key_length > MAX_PROVING_KEY_BYTES
        || expected != bytes.len()
    {
        return Err(CeremonyError::InvalidContribution);
    }
    let mut input = bytes;
    let value = Phase2Artifact::deserialize_compressed(&mut input)
        .map_err(|_| CeremonyError::InvalidContribution)?;
    if !input.is_empty() || encode_phase2_artifact(&value)? != bytes {
        return Err(CeremonyError::InvalidContribution);
    }
    decode(&value.proving_key)?;
    Ok(value)
}

/// Verify every invariant and pairing equation for one phase-2 contribution.
pub fn verify_contribution(previous: &[u8], next: &[u8]) -> Result<(), CeremonyError> {
    let old = decode(previous)?;
    let new = decode(next)?;
    if old == new
        || old.vk.alpha_g1 != new.vk.alpha_g1
        || old.vk.beta_g2 != new.vk.beta_g2
        || old.vk.gamma_g2 != new.vk.gamma_g2
        || old.vk.gamma_abc_g1 != new.vk.gamma_abc_g1
        || old.beta_g1 != new.beta_g1
        || old.a_query != new.a_query
        || old.b_g1_query != new.b_g1_query
        || old.b_g2_query != new.b_g2_query
        || old.h_query.len() != new.h_query.len()
        || old.l_query.len() != new.l_query.len()
        || has_structural_identity(&old)
        || has_structural_identity(&new)
    {
        return Err(CeremonyError::InvalidContribution);
    }
    if Bn254::pairing(new.delta_g1, old.vk.delta_g2)
        != Bn254::pairing(old.delta_g1, new.vk.delta_g2)
    {
        return Err(CeremonyError::AlgebraicVerificationFailed);
    }
    let pairs: Vec<_> = old
        .h_query
        .iter()
        .zip(&new.h_query)
        .chain(old.l_query.iter().zip(&new.l_query))
        .collect();
    if pairs
        .iter()
        .any(|(before, after)| before.is_zero() != after.is_zero())
    {
        return Err(CeremonyError::AlgebraicVerificationFailed);
    }
    // Fiat-Shamir random linear combination batches every query equation into
    // one pairing check without permitting adversarial cancellation.
    let mut digest = Sha256::new();
    digest.update(b"DOM:usdom-groth16-phase2-batch:v1");
    digest.update(previous);
    digest.update(next);
    let mut challenge = Fr::from_be_bytes_mod_order(&digest.finalize());
    if challenge.is_zero() {
        challenge = Fr::one();
    }
    let mut coefficient = Fr::one();
    let mut old_aggregate = <Bn254 as Pairing>::G1::zero();
    let mut new_aggregate = <Bn254 as Pairing>::G1::zero();
    for (before, after) in pairs {
        old_aggregate += before.mul_bigint(coefficient.into_bigint());
        new_aggregate += after.mul_bigint(coefficient.into_bigint());
        coefficient *= challenge;
    }
    if Bn254::pairing(new_aggregate.into_affine(), new.vk.delta_g2)
        != Bn254::pairing(old_aggregate.into_affine(), old.vk.delta_g2)
    {
        return Err(CeremonyError::AlgebraicVerificationFailed);
    }
    Ok(())
}

/// Extract the checked canonical verifying key derived from a proving key.
pub fn extract_verifying_key(proving_key: &[u8]) -> Result<Vec<u8>, CeremonyError> {
    let key = decode(proving_key)?;
    if has_structural_identity(&key) {
        return Err(CeremonyError::InvalidProvingKey);
    }
    let mut bytes = Vec::new();
    key.vk
        .serialize_compressed(&mut bytes)
        .map_err(|_| CeremonyError::InvalidProvingKey)?;
    Ok(bytes)
}

/// Validate final PK↔VK derivation and positive burn/transfer proofs, including
/// failure after each of the nine public inputs is independently changed.
pub fn validate_final_key<R: RngCore + CryptoRng>(
    proving_key: &[u8],
    rng: &mut R,
) -> Result<(CircuitFingerprint, Vec<u8>, [u8; 32]), CeremonyError> {
    let key = decode(proving_key)?;
    let fingerprint = circuit_fingerprint()?;
    if key.vk.gamma_abc_g1.len() != fingerprint.instance_variables
        || key.a_query.len() != fingerprint.instance_variables + fingerprint.witness_variables
        || key.b_g1_query.len() != key.a_query.len()
        || key.b_g2_query.len() != key.a_query.len()
        || key.l_query.len() != fingerprint.witness_variables
        || key.h_query.len() != fingerprint.domain_size - 1
    {
        return Err(CeremonyError::InvalidContribution);
    }
    let vk = extract_verifying_key(proving_key)?;
    if vk.len() > MAX_VERIFYING_KEY_BYTES {
        return Err(CeremonyError::InvalidProvingKey);
    }
    let config_hash = crate::verifier::SpendVerifier::from_bytes(&vk)
        .map_err(|_| CeremonyError::InvalidProvingKey)?
        .config_hash();
    let prepared = prepare_verifying_key(&key.vk);
    for circuit in [
        crate::circuit::tests_support::valid_burn_circuit(),
        crate::circuit::tests_support::valid_transfer_circuit(),
    ] {
        let proof =
            Groth16::<Bn254>::create_random_proof_with_reduction(circuit.clone(), &key, rng)
                .map_err(|_| CeremonyError::InvalidContribution)?;
        let inputs = circuit.statement.public_inputs();
        if !Groth16::<Bn254>::verify_proof(&prepared, &proof, &inputs)
            .map_err(|_| CeremonyError::AlgebraicVerificationFailed)?
        {
            return Err(CeremonyError::AlgebraicVerificationFailed);
        }
        for index in 0..inputs.len() {
            let mut changed = inputs;
            changed[index] += Fr::one();
            if Groth16::<Bn254>::verify_proof(&prepared, &proof, &changed)
                .map_err(|_| CeremonyError::AlgebraicVerificationFailed)?
            {
                return Err(CeremonyError::AlgebraicVerificationFailed);
            }
        }
    }
    Ok((fingerprint, vk, *config_hash.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{G1Affine, G2Affine};
    use ark_groth16::Groth16;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn phase2_transcript_rejects_zero_domain_components_before_key_processing() {
        let context = Phase2Context {
            release: [1; 32],
            circuit: [2; 32],
            contributor: [3; 32],
            ordinal: 1,
            previous_transcript: [0; 32],
        };
        let proof = Phase2KnowledgeProof {
            commitment_g1: G1Affine::generator(),
            commitment_g2: G2Affine::generator(),
            response: Fr::one(),
        };
        for invalid in [
            Phase2Context {
                ordinal: 0,
                ..context.clone()
            },
            Phase2Context {
                release: [0; 32],
                ..context.clone()
            },
            Phase2Context {
                circuit: [0; 32],
                ..context.clone()
            },
            Phase2Context {
                contributor: [0; 32],
                ..context.clone()
            },
        ] {
            assert_eq!(
                phase2_challenge(&[], &[], &invalid, &proof),
                Err(CeremonyError::InvalidContribution)
            );
        }
    }

    #[test]
    fn phase2_artifact_rejects_hostile_key_length_before_deserialization() {
        let mut hostile = vec![0u8; SERIALIZED_LENGTH_BYTES + PHASE2_PROOF_BYTES];
        hostile[..SERIALIZED_LENGTH_BYTES].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            decode_phase2_artifact(&hostile),
            Err(CeremonyError::InvalidContribution)
        );

        hostile[..SERIALIZED_LENGTH_BYTES].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(
            decode_phase2_artifact(&hostile),
            Err(CeremonyError::InvalidContribution)
        );
    }

    #[test]
    fn valid_contribution_preserves_proving_and_verifying_relation() {
        let mut rng = StdRng::seed_from_u64(0x4345_5245_4d4f_4e59);
        let circuit = crate::circuit::tests_support::valid_burn_circuit();
        let original =
            Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit.clone(), &mut rng)
                .unwrap();
        let old = encode(&original).unwrap();
        let context = Phase2Context {
            release: [1; 32],
            circuit: [2; 32],
            contributor: [3; 32],
            ordinal: 1,
            previous_transcript: [4; 32],
        };
        let artifact = contribute_with_proof(&old, &context, &mut rng).unwrap();
        let new = artifact.proving_key.clone();
        verify_contribution_with_proof(&old, &new, &context, &artifact.proof).unwrap();
        let mut bad_proof = artifact.proof.clone();
        bad_proof.response += Fr::one();
        assert!(verify_contribution_with_proof(&old, &new, &context, &bad_proof).is_err());
        let mut bad_context = context.clone();
        bad_context.contributor[0] ^= 1;
        assert!(verify_contribution_with_proof(&old, &new, &bad_context, &artifact.proof).is_err());
        for invalid in [
            Phase2Context {
                ordinal: 0,
                ..context.clone()
            },
            Phase2Context {
                release: [0; 32],
                ..context.clone()
            },
            Phase2Context {
                circuit: [0; 32],
                ..context.clone()
            },
            Phase2Context {
                contributor: [0; 32],
                ..context.clone()
            },
        ] {
            assert!(verify_contribution_with_proof(&old, &new, &invalid, &artifact.proof).is_err());
        }
        let encoded_artifact = encode_phase2_artifact(&artifact).unwrap();
        assert_eq!(decode_phase2_artifact(&encoded_artifact).unwrap(), artifact);
        let mut noncanonical_artifact = encoded_artifact;
        noncanonical_artifact.push(0);
        assert!(decode_phase2_artifact(&noncanonical_artifact).is_err());
        verify_contribution(&old, &new).unwrap();
        let updated = decode(&new).unwrap();
        let proof = Groth16::<Bn254>::create_random_proof_with_reduction(
            circuit.clone(),
            &updated,
            &mut rng,
        )
        .unwrap();
        assert!(Groth16::<Bn254>::verify_proof(
            &ark_groth16::prepare_verifying_key(&updated.vk),
            &proof,
            &circuit.statement.public_inputs()
        )
        .unwrap());
        let vk = extract_verifying_key(&new).unwrap();
        let mut expected = Vec::new();
        updated.vk.serialize_compressed(&mut expected).unwrap();
        assert_eq!(vk, expected);
        let mut changed = decode(&new).unwrap();
        changed.h_query[0] = original.h_query[0];
        assert_eq!(
            verify_contribution(&old, &encode(&changed).unwrap()),
            Err(CeremonyError::AlgebraicVerificationFailed)
        );
        let mut invariant = decode(&new).unwrap();
        invariant.beta_g1 = Default::default();
        assert_eq!(
            verify_contribution(&old, &encode(&invariant).unwrap()),
            Err(CeremonyError::InvalidContribution)
        );
        assert_eq!(
            verify_contribution(&old, &old),
            Err(CeremonyError::InvalidContribution)
        );
        let (fingerprint, derived, config_hash) = validate_final_key(&new, &mut rng).unwrap();
        assert_eq!(fingerprint.instance_variables, 10);
        assert_eq!(derived, vk);
        assert_ne!(config_hash, [0; 32]);
    }
}
