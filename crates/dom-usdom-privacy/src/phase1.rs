//! Verifiable BN254 Powers-of-Tau Phase 1 and exact Groth16 specialization.
//!
//! The initial accumulator contains only public generators (all trapdoors are
//! one). Every contributor multiplies tau, alpha and beta by independently
//! sampled nonzero, nonunit scalars. A generalized Schnorr proof demonstrates
//! knowledge of those scalars and is Fiat-Shamir-bound to the release,
//! contributor identity, circuit fingerprint and complete before/after states.

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::ceremony::{circuit_fingerprint, CeremonyError};

const MAX_DEGREE: usize = 1 << 20;
const SERIALIZED_LENGTH_BYTES: usize = 8;
const COMPRESSED_G1_BYTES: usize = 32;
const COMPRESSED_G2_BYTES: usize = 64;
const COMPRESSED_FR_BYTES: usize = 32;
const KNOWLEDGE_PROOF_BYTES: usize =
    3 * COMPRESSED_G1_BYTES + 2 * COMPRESSED_G2_BYTES + 3 * COMPRESSED_FR_BYTES;

/// Public transcript binding for one contribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContributionContext {
    /// Frozen release commitment.
    pub release: [u8; 32],
    /// Exact circuit fingerprint.
    pub circuit: [u8; 32],
    /// Contributor public identity commitment.
    pub contributor: [u8; 32],
    /// One-based contribution position.
    pub ordinal: u64,
    /// Hash of the preceding transcript record.
    pub previous_transcript: [u8; 32],
}

/// Universal Phase-1 accumulator. Alpha and beta powers are sufficient for
/// exact Groth16 specialization; gamma is deliberately the public nonzero one.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase1Accumulator {
    /// Consecutive G1 powers of tau.
    pub tau_g1: Vec<G1Affine>,
    /// Consecutive G2 powers of tau.
    pub tau_g2: Vec<G2Affine>,
    /// Alpha-scaled G1 powers of tau.
    pub alpha_tau_g1: Vec<G1Affine>,
    /// Beta-scaled G1 powers of tau.
    pub beta_tau_g1: Vec<G1Affine>,
    /// Beta in G2.
    pub beta_g2: G2Affine,
}

/// Generalized Schnorr/Chaum-Pedersen proof of knowledge for tau, alpha and beta.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KnowledgeProof {
    /// Tau nonce commitment in G1.
    pub tau_commit_g1: G1Affine,
    /// Tau nonce commitment in G2.
    pub tau_commit_g2: G2Affine,
    /// Alpha nonce commitment in G1.
    pub alpha_commit_g1: G1Affine,
    /// Beta nonce commitment in G1.
    pub beta_commit_g1: G1Affine,
    /// Beta nonce commitment in G2.
    pub beta_commit_g2: G2Affine,
    /// Fiat-Shamir tau response.
    pub tau_response: Fr,
    /// Fiat-Shamir alpha response.
    pub alpha_response: Fr,
    /// Fiat-Shamir beta response.
    pub beta_response: Fr,
}

/// Self-contained result of one Phase-1 contribution.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ContributionArtifact {
    /// Updated accumulator.
    pub accumulator: Phase1Accumulator,
    /// Proof of knowledge for this exact update.
    pub proof: KnowledgeProof,
}

fn serialize<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, CeremonyError> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|_| CeremonyError::InvalidContribution)?;
    Ok(bytes)
}

fn framed_count(bytes: &[u8], cursor: &mut usize) -> Result<usize, CeremonyError> {
    let end = cursor
        .checked_add(SERIALIZED_LENGTH_BYTES)
        .ok_or(CeremonyError::InvalidContribution)?;
    let encoded: [u8; SERIALIZED_LENGTH_BYTES] = bytes
        .get(*cursor..end)
        .ok_or(CeremonyError::InvalidContribution)?
        .try_into()
        .map_err(|_| CeremonyError::InvalidContribution)?;
    *cursor = end;
    usize::try_from(u64::from_le_bytes(encoded)).map_err(|_| CeremonyError::InvalidContribution)
}

fn skip_framed_points(
    bytes: &[u8],
    cursor: &mut usize,
    point_bytes: usize,
) -> Result<usize, CeremonyError> {
    let count = framed_count(bytes, cursor)?;
    if !(3..=MAX_DEGREE + 1).contains(&count) {
        return Err(CeremonyError::InvalidContribution);
    }
    let end = cursor
        .checked_add(
            count
                .checked_mul(point_bytes)
                .ok_or(CeremonyError::InvalidContribution)?,
        )
        .ok_or(CeremonyError::InvalidContribution)?;
    if end > bytes.len() {
        return Err(CeremonyError::InvalidContribution);
    }
    *cursor = end;
    Ok(count)
}

/// Validate every attacker-controlled vector length before Arkworks is allowed
/// to deserialize and allocate it. `CanonicalDeserialize` reads a vector's
/// declared `u64` length before discovering that the input is truncated; a
/// tiny malicious artifact could otherwise request an enormous allocation.
fn preflight_accumulator_frame(bytes: &[u8], trailing: usize) -> Result<(), CeremonyError> {
    let mut cursor = 0usize;
    let degree_count = skip_framed_points(bytes, &mut cursor, COMPRESSED_G1_BYTES)?;
    for point_bytes in [
        COMPRESSED_G2_BYTES,
        COMPRESSED_G1_BYTES,
        COMPRESSED_G1_BYTES,
    ] {
        if skip_framed_points(bytes, &mut cursor, point_bytes)? != degree_count {
            return Err(CeremonyError::InvalidContribution);
        }
    }
    cursor = cursor
        .checked_add(COMPRESSED_G2_BYTES)
        .ok_or(CeremonyError::InvalidContribution)?;
    let expected = cursor
        .checked_add(trailing)
        .ok_or(CeremonyError::InvalidContribution)?;
    if expected != bytes.len() {
        return Err(CeremonyError::InvalidContribution);
    }
    Ok(())
}

/// Canonically encode an accumulator after validating all structural bounds.
pub fn encode_accumulator(value: &Phase1Accumulator) -> Result<Vec<u8>, CeremonyError> {
    validate_shape(value)?;
    serialize(value)
}

/// Decode one canonical accumulator, validating points, subgroup and bounds.
pub fn decode_accumulator(bytes: &[u8]) -> Result<Phase1Accumulator, CeremonyError> {
    if bytes.is_empty() || bytes.len() > 512 * 1024 * 1024 {
        return Err(CeremonyError::InvalidContribution);
    }
    preflight_accumulator_frame(bytes, 0)?;
    let mut input = bytes;
    let value = Phase1Accumulator::deserialize_with_mode(&mut input, Compress::Yes, Validate::Yes)
        .map_err(|_| CeremonyError::InvalidContribution)?;
    if !input.is_empty() || encode_accumulator(&value)? != bytes {
        return Err(CeremonyError::InvalidContribution);
    }
    Ok(value)
}

/// Canonically encode a contribution proof.
pub fn encode_proof(value: &KnowledgeProof) -> Result<Vec<u8>, CeremonyError> {
    serialize(value)
}

/// Decode a canonical, subgroup-checked contribution proof.
pub fn decode_proof(bytes: &[u8]) -> Result<KnowledgeProof, CeremonyError> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(CeremonyError::InvalidContribution);
    }
    let mut input = bytes;
    let value = KnowledgeProof::deserialize_with_mode(&mut input, Compress::Yes, Validate::Yes)
        .map_err(|_| CeremonyError::InvalidContribution)?;
    if !input.is_empty() || encode_proof(&value)? != bytes {
        return Err(CeremonyError::InvalidContribution);
    }
    Ok(value)
}

/// Encode a complete contribution artifact canonically.
pub fn encode_artifact(value: &ContributionArtifact) -> Result<Vec<u8>, CeremonyError> {
    validate_shape(&value.accumulator)?;
    serialize(value)
}

/// Decode a canonical, bounded and subgroup-checked contribution artifact.
pub fn decode_artifact(bytes: &[u8]) -> Result<ContributionArtifact, CeremonyError> {
    if bytes.is_empty() || bytes.len() > 512 * 1024 * 1024 {
        return Err(CeremonyError::InvalidContribution);
    }
    preflight_accumulator_frame(bytes, KNOWLEDGE_PROOF_BYTES)?;
    let mut input = bytes;
    let value =
        ContributionArtifact::deserialize_with_mode(&mut input, Compress::Yes, Validate::Yes)
            .map_err(|_| CeremonyError::InvalidContribution)?;
    if !input.is_empty() || encode_artifact(&value)? != bytes {
        return Err(CeremonyError::InvalidContribution);
    }
    Ok(value)
}

fn validate_shape(value: &Phase1Accumulator) -> Result<usize, CeremonyError> {
    if value.tau_g1.len() < 3 || value.tau_g1.len() > MAX_DEGREE + 1 {
        return Err(CeremonyError::InvalidContribution);
    }
    let degree = value.tau_g1.len() - 1;
    if value.tau_g2.len() != degree + 1
        || value.alpha_tau_g1.len() != degree + 1
        || value.beta_tau_g1.len() != degree + 1
        || value.tau_g1.iter().any(AffineRepr::is_zero)
        || value.tau_g2.iter().any(AffineRepr::is_zero)
        || value.alpha_tau_g1.iter().any(AffineRepr::is_zero)
        || value.beta_tau_g1.iter().any(AffineRepr::is_zero)
        || value.beta_g2.is_zero()
    {
        return Err(CeremonyError::InvalidContribution);
    }
    Ok(degree)
}

/// Create the public, trapdoor-free starting accumulator.
pub fn initialize(degree: usize) -> Result<Phase1Accumulator, CeremonyError> {
    if !(2..=MAX_DEGREE).contains(&degree) {
        return Err(CeremonyError::InvalidContribution);
    }
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    Ok(Phase1Accumulator {
        tau_g1: vec![g1; degree + 1],
        tau_g2: vec![g2; degree + 1],
        alpha_tau_g1: vec![g1; degree + 1],
        beta_tau_g1: vec![g1; degree + 1],
        beta_g2: g2,
    })
}

/// Prove that an accumulator is the deterministic, trapdoor-free generator state.
pub fn verify_initial(value: &Phase1Accumulator) -> Result<(), CeremonyError> {
    let degree = validate_shape(value)?;
    if *value != initialize(degree)? {
        return Err(CeremonyError::AlgebraicVerificationFailed);
    }
    Ok(())
}

fn hash_context(d: &mut Sha256, context: &ContributionContext) {
    d.update(b"DOM:usdom-bn254-phase1-pok:v1");
    d.update(context.release);
    d.update(context.circuit);
    d.update(context.contributor);
    d.update(context.ordinal.to_be_bytes());
    d.update(context.previous_transcript);
}

fn validate_context(context: &ContributionContext) -> Result<(), CeremonyError> {
    if context.ordinal == 0
        || context.release == [0; 32]
        || context.circuit == [0; 32]
        || context.contributor == [0; 32]
    {
        return Err(CeremonyError::InvalidContribution);
    }
    Ok(())
}

fn challenge(
    before: &Phase1Accumulator,
    after: &Phase1Accumulator,
    context: &ContributionContext,
    p: &KnowledgeProof,
) -> Result<Fr, CeremonyError> {
    validate_context(context)?;
    let mut d = Sha256::new();
    hash_context(&mut d, context);
    d.update(serialize(before)?);
    d.update(serialize(after)?);
    d.update(serialize(&p.tau_commit_g1)?);
    d.update(serialize(&p.tau_commit_g2)?);
    d.update(serialize(&p.alpha_commit_g1)?);
    d.update(serialize(&p.beta_commit_g1)?);
    d.update(serialize(&p.beta_commit_g2)?);
    let mut c = Fr::from_be_bytes_mod_order(&d.finalize());
    if c.is_zero() {
        c = Fr::one();
    }
    Ok(c)
}

fn nontrivial<R: RngCore + CryptoRng>(rng: &mut R) -> Fr {
    loop {
        let mut x = Fr::rand(rng);
        if !x.is_zero() && !x.is_one() {
            return x;
        }
        x.zeroize();
    }
}

fn apply_scalars<R: RngCore + CryptoRng>(
    before: &Phase1Accumulator,
    context: &ContributionContext,
    rng: &mut R,
    mut tau: Fr,
    mut alpha: Fr,
    mut beta: Fr,
) -> Result<(Phase1Accumulator, KnowledgeProof), CeremonyError> {
    validate_shape(before)?;
    let mut after = before.clone();
    let mut power = Fr::one();
    for i in 0..after.tau_g1.len() {
        after.tau_g1[i] = before.tau_g1[i]
            .mul_bigint(power.into_bigint())
            .into_affine();
        after.tau_g2[i] = before.tau_g2[i]
            .mul_bigint(power.into_bigint())
            .into_affine();
        after.alpha_tau_g1[i] = before.alpha_tau_g1[i]
            .mul_bigint((power * alpha).into_bigint())
            .into_affine();
        after.beta_tau_g1[i] = before.beta_tau_g1[i]
            .mul_bigint((power * beta).into_bigint())
            .into_affine();
        power *= tau;
    }
    after.beta_g2 = before.beta_g2.mul_bigint(beta.into_bigint()).into_affine();
    let mut rt = nontrivial(rng);
    let mut ra = nontrivial(rng);
    let mut rb = nontrivial(rng);
    let mut proof = KnowledgeProof {
        tau_commit_g1: before.tau_g1[1].mul_bigint(rt.into_bigint()).into_affine(),
        tau_commit_g2: before.tau_g2[1].mul_bigint(rt.into_bigint()).into_affine(),
        alpha_commit_g1: before.alpha_tau_g1[0]
            .mul_bigint(ra.into_bigint())
            .into_affine(),
        beta_commit_g1: before.beta_tau_g1[0]
            .mul_bigint(rb.into_bigint())
            .into_affine(),
        beta_commit_g2: before.beta_g2.mul_bigint(rb.into_bigint()).into_affine(),
        tau_response: Fr::zero(),
        alpha_response: Fr::zero(),
        beta_response: Fr::zero(),
    };
    let c = challenge(before, &after, context, &proof)?;
    proof.tau_response = rt + c * tau;
    proof.alpha_response = ra + c * alpha;
    proof.beta_response = rb + c * beta;
    tau.zeroize();
    alpha.zeroize();
    beta.zeroize();
    rt.zeroize();
    ra.zeroize();
    rb.zeroize();
    verify_contribution(before, &after, context, &proof)?;
    Ok((after, proof))
}

/// Add one independently randomized Phase-1 contribution and its bound PoK.
pub fn contribute<R: RngCore + CryptoRng>(
    before: &Phase1Accumulator,
    context: &ContributionContext,
    rng: &mut R,
) -> Result<(Phase1Accumulator, KnowledgeProof), CeremonyError> {
    let tau = nontrivial(rng);
    let alpha = nontrivial(rng);
    let beta = nontrivial(rng);
    apply_scalars(before, context, rng, tau, alpha, beta)
}

fn schnorr_g1(base: G1Affine, result: G1Affine, commit: G1Affine, response: Fr, c: Fr) -> bool {
    base.mul_bigint(response.into_bigint())
        == commit.into_group() + result.mul_bigint(c.into_bigint())
}
fn schnorr_g2(base: G2Affine, result: G2Affine, commit: G2Affine, response: Fr, c: Fr) -> bool {
    base.mul_bigint(response.into_bigint())
        == commit.into_group() + result.mul_bigint(c.into_bigint())
}

/// Independently verify the complete accumulator update and contributor PoK.
pub fn verify_contribution(
    before: &Phase1Accumulator,
    after: &Phase1Accumulator,
    context: &ContributionContext,
    proof: &KnowledgeProof,
) -> Result<(), CeremonyError> {
    let degree = validate_shape(before)?;
    if validate_shape(after)? != degree || before == after {
        return Err(CeremonyError::InvalidContribution);
    }
    if before.tau_g1[0] != after.tau_g1[0]
        || before.tau_g2[0] != after.tau_g2[0]
        || before.tau_g1[1] == after.tau_g1[1]
        || before.alpha_tau_g1[0] == after.alpha_tau_g1[0]
        || before.beta_tau_g1[0] == after.beta_tau_g1[0]
    {
        return Err(CeremonyError::AlgebraicVerificationFailed);
    }
    if Bn254::pairing(after.alpha_tau_g1[0], before.tau_g2[0])
        == Bn254::pairing(before.alpha_tau_g1[0], before.tau_g2[0])
        || Bn254::pairing(after.beta_tau_g1[0], before.tau_g2[0])
            != Bn254::pairing(before.beta_tau_g1[0], after.beta_g2)
    {
        return Err(CeremonyError::AlgebraicVerificationFailed);
    }
    let c = challenge(before, after, context, proof)?;
    // Random-linear-combination checks make verification O(degree) group
    // additions plus a constant number of pairings. The Fiat-Shamir challenge
    // commits to every point, so an altered first/middle/last relation is
    // accepted with probability at most 1/|Fr| in the random-oracle model.
    let mut coefficient = Fr::one();
    let mut tau_g1_left = <Bn254 as Pairing>::G1::zero();
    let mut tau_g1_right = <Bn254 as Pairing>::G1::zero();
    let mut alpha_left = <Bn254 as Pairing>::G1::zero();
    let mut alpha_right = <Bn254 as Pairing>::G1::zero();
    let mut beta_left = <Bn254 as Pairing>::G1::zero();
    let mut beta_right = <Bn254 as Pairing>::G1::zero();
    let mut tau_g2_left = <Bn254 as Pairing>::G2::zero();
    let mut tau_g2_right = <Bn254 as Pairing>::G2::zero();
    for i in 1..=degree {
        tau_g1_left += after.tau_g1[i].mul_bigint(coefficient.into_bigint());
        tau_g1_right += after.tau_g1[i - 1].mul_bigint(coefficient.into_bigint());
        alpha_left += after.alpha_tau_g1[i].mul_bigint(coefficient.into_bigint());
        alpha_right += after.alpha_tau_g1[i - 1].mul_bigint(coefficient.into_bigint());
        beta_left += after.beta_tau_g1[i].mul_bigint(coefficient.into_bigint());
        beta_right += after.beta_tau_g1[i - 1].mul_bigint(coefficient.into_bigint());
        tau_g2_left += after.tau_g2[i].mul_bigint(coefficient.into_bigint());
        tau_g2_right += after.tau_g2[i - 1].mul_bigint(coefficient.into_bigint());
        coefficient *= c;
    }
    if Bn254::pairing(tau_g1_left.into_affine(), before.tau_g2[0])
        != Bn254::pairing(tau_g1_right.into_affine(), after.tau_g2[1])
        || Bn254::pairing(before.tau_g1[0], tau_g2_left.into_affine())
            != Bn254::pairing(after.tau_g1[1], tau_g2_right.into_affine())
        || Bn254::pairing(alpha_left.into_affine(), before.tau_g2[0])
            != Bn254::pairing(alpha_right.into_affine(), after.tau_g2[1])
        || Bn254::pairing(beta_left.into_affine(), before.tau_g2[0])
            != Bn254::pairing(beta_right.into_affine(), after.tau_g2[1])
    {
        return Err(CeremonyError::AlgebraicVerificationFailed);
    }
    if !schnorr_g1(
        before.tau_g1[1],
        after.tau_g1[1],
        proof.tau_commit_g1,
        proof.tau_response,
        c,
    ) || !schnorr_g2(
        before.tau_g2[1],
        after.tau_g2[1],
        proof.tau_commit_g2,
        proof.tau_response,
        c,
    ) || !schnorr_g1(
        before.alpha_tau_g1[0],
        after.alpha_tau_g1[0],
        proof.alpha_commit_g1,
        proof.alpha_response,
        c,
    ) || !schnorr_g1(
        before.beta_tau_g1[0],
        after.beta_tau_g1[0],
        proof.beta_commit_g1,
        proof.beta_response,
        c,
    ) || !schnorr_g2(
        before.beta_g2,
        after.beta_g2,
        proof.beta_commit_g2,
        proof.beta_response,
        c,
    ) {
        return Err(CeremonyError::AlgebraicVerificationFailed);
    }
    Ok(())
}

fn production_matrices(
) -> Result<(ark_relations::r1cs::ConstraintMatrices<Fr>, usize), CeremonyError> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    crate::circuit::SpendCircuit::default()
        .generate_constraints(cs.clone())
        .map_err(|_| CeremonyError::InvalidContribution)?;
    cs.finalize();
    let matrices = cs.to_matrices().ok_or(CeremonyError::InvalidContribution)?;
    let size = GeneralEvaluationDomain::<Fr>::new(
        matrices.num_constraints + matrices.num_instance_variables,
    )
    .ok_or(CeremonyError::InvalidContribution)?
    .size();
    Ok((matrices, size))
}

fn accumulate_rows_g1(
    rows: &[Vec<(Fr, usize)>],
    lagrange: &[<Bn254 as Pairing>::G1],
    variables: usize,
) -> Vec<<Bn254 as Pairing>::G1> {
    let mut out = vec![<Bn254 as Pairing>::G1::zero(); variables];
    for (row, terms) in rows.iter().enumerate() {
        for (coefficient, index) in terms {
            out[*index] += lagrange[row].mul_bigint(coefficient.into_bigint());
        }
    }
    out
}
fn accumulate_rows_g2(
    rows: &[Vec<(Fr, usize)>],
    lagrange: &[<Bn254 as Pairing>::G2],
    variables: usize,
) -> Vec<<Bn254 as Pairing>::G2> {
    let mut out = vec![<Bn254 as Pairing>::G2::zero(); variables];
    for (row, terms) in rows.iter().enumerate() {
        for (coefficient, index) in terms {
            out[*index] += lagrange[row].mul_bigint(coefficient.into_bigint());
        }
    }
    out
}

/// Specialize a verified universal accumulator to the exact production R1CS.
/// Gamma and the initial delta are public one; subsequent Phase-2 contributions
/// make delta unknown before the key can be accepted by production.
pub fn specialize(acc: &Phase1Accumulator) -> Result<ProvingKey<Bn254>, CeremonyError> {
    validate_shape(acc)?;
    let fingerprint = circuit_fingerprint()?;
    let (matrices, n) = production_matrices()?;
    let inputs = matrices.num_instance_variables;
    let variables = inputs + matrices.num_witness_variables;
    if fingerprint.domain_size != n || acc.tau_g1.len() < 2 * n {
        return Err(CeremonyError::InvalidContribution);
    }
    let domain = GeneralEvaluationDomain::<Fr>::new(n).ok_or(CeremonyError::InvalidContribution)?;
    let mut tau_g1: Vec<_> = acc.tau_g1[..n].iter().map(|p| p.into_group()).collect();
    domain.ifft_in_place(&mut tau_g1);
    let mut tau_g2: Vec<_> = acc.tau_g2[..n].iter().map(|p| p.into_group()).collect();
    domain.ifft_in_place(&mut tau_g2);
    let mut alpha_g1: Vec<_> = acc.alpha_tau_g1[..n]
        .iter()
        .map(|p| p.into_group())
        .collect();
    domain.ifft_in_place(&mut alpha_g1);
    let mut beta_g1: Vec<_> = acc.beta_tau_g1[..n]
        .iter()
        .map(|p| p.into_group())
        .collect();
    domain.ifft_in_place(&mut beta_g1);
    let mut a_query = accumulate_rows_g1(&matrices.a, &tau_g1, variables);
    for i in 0..inputs {
        a_query[i] += tau_g1[matrices.num_constraints + i];
    }
    let b_g1_query = accumulate_rows_g1(&matrices.b, &tau_g1, variables);
    let b_g2_query = accumulate_rows_g2(&matrices.b, &tau_g2, variables);
    let mut beta_a = accumulate_rows_g1(&matrices.a, &beta_g1, variables);
    for i in 0..inputs {
        beta_a[i] += beta_g1[matrices.num_constraints + i];
    }
    let alpha_b = accumulate_rows_g1(&matrices.b, &alpha_g1, variables);
    let plain_c = accumulate_rows_g1(&matrices.c, &tau_g1, variables);
    let combine = |i: usize| (beta_a[i] + alpha_b[i] + plain_c[i]).into_affine();
    let gamma_abc_g1 = (0..inputs).map(combine).collect();
    let l_query = (inputs..variables).map(combine).collect();
    let h_query = (0..n - 1)
        .map(|i| (acc.tau_g1[n + i].into_group() - acc.tau_g1[i]).into_affine())
        .collect();
    Ok(ProvingKey {
        vk: VerifyingKey {
            alpha_g1: acc.alpha_tau_g1[0],
            beta_g2: acc.beta_g2,
            gamma_g2: acc.tau_g2[0],
            delta_g2: acc.tau_g2[0],
            gamma_abc_g1,
        },
        beta_g1: acc.beta_tau_g1[0],
        delta_g1: acc.tau_g1[0],
        a_query: a_query.into_iter().map(|p| p.into_affine()).collect(),
        b_g1_query: b_g1_query.into_iter().map(|p| p.into_affine()).collect(),
        b_g2_query: b_g2_query.into_iter().map(|p| p.into_affine()).collect(),
        h_query,
        l_query,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::scalar_mul::BatchMulPreprocessing;
    use rand::{rngs::StdRng, SeedableRng};
    fn ctx() -> ContributionContext {
        ContributionContext {
            release: [1; 32],
            circuit: [2; 32],
            contributor: [3; 32],
            ordinal: 1,
            previous_transcript: [4; 32],
        }
    }
    fn known_accumulator(degree: usize, tau: Fr, alpha: Fr, beta: Fr) -> Phase1Accumulator {
        let mut powers = Vec::with_capacity(degree + 1);
        let mut p = Fr::one();
        for _ in 0..=degree {
            powers.push(p);
            p *= tau;
        }
        let alpha_powers: Vec<_> = powers.iter().map(|p| *p * alpha).collect();
        let beta_powers: Vec<_> = powers.iter().map(|p| *p * beta).collect();
        let g1 = BatchMulPreprocessing::new(G1Affine::generator().into_group(), 4 * (degree + 1));
        let g2 = BatchMulPreprocessing::new(G2Affine::generator().into_group(), degree + 2);
        Phase1Accumulator {
            tau_g1: g1.batch_mul(&powers),
            tau_g2: g2.batch_mul(&powers),
            alpha_tau_g1: g1.batch_mul(&alpha_powers),
            beta_tau_g1: g1.batch_mul(&beta_powers),
            beta_g2: G2Affine::generator()
                .mul_bigint(beta.into_bigint())
                .into_affine(),
        }
    }
    #[test]
    fn phase1_contribution_and_pok_reject_mutations() {
        let mut r = StdRng::seed_from_u64(7);
        let before = initialize(8).unwrap();
        let (after, p) = contribute(&before, &ctx(), &mut r).unwrap();
        verify_contribution(&before, &after, &ctx(), &p).unwrap();
        let mut q = p.clone();
        q.tau_response += Fr::one();
        assert!(verify_contribution(&before, &after, &ctx(), &q).is_err());
        let mut c = ctx();
        c.release[0] ^= 1;
        assert!(verify_contribution(&before, &after, &c, &p).is_err());
        for invalid in [
            ContributionContext {
                ordinal: 0,
                ..ctx()
            },
            ContributionContext {
                release: [0; 32],
                ..ctx()
            },
            ContributionContext {
                circuit: [0; 32],
                ..ctx()
            },
            ContributionContext {
                contributor: [0; 32],
                ..ctx()
            },
        ] {
            assert!(verify_contribution(&before, &after, &invalid, &p).is_err());
        }
        for index in [1, 4, 8] {
            let mut bad = after.clone();
            bad.tau_g1[index] = bad.tau_g1[index - 1];
            assert!(verify_contribution(&before, &bad, &ctx(), &p).is_err());
        }
        let encoded = encode_accumulator(&after).unwrap();
        assert_eq!(decode_accumulator(&encoded).unwrap(), after);
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_accumulator(&trailing).is_err());
    }

    #[test]
    fn phase1_decoders_reject_hostile_vector_lengths_before_deserialization() {
        let accumulator = initialize(2).unwrap();
        let encoded = encode_accumulator(&accumulator).unwrap();

        let mut hostile_first = encoded.clone();
        hostile_first[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            decode_accumulator(&hostile_first),
            Err(CeremonyError::InvalidContribution)
        );

        // The second vector follows the three compressed G1 points in the
        // first vector. A valid leading vector must not let a later forged
        // length reach Arkworks' allocation path either.
        let mut hostile_second = encoded;
        let second_length = 8 + 3 * COMPRESSED_G1_BYTES;
        hostile_second[second_length..second_length + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            decode_accumulator(&hostile_second),
            Err(CeremonyError::InvalidContribution)
        );

        let artifact = ContributionArtifact {
            accumulator,
            proof: KnowledgeProof {
                tau_commit_g1: G1Affine::generator(),
                tau_commit_g2: G2Affine::generator(),
                alpha_commit_g1: G1Affine::generator(),
                beta_commit_g1: G1Affine::generator(),
                beta_commit_g2: G2Affine::generator(),
                tau_response: Fr::one(),
                alpha_response: Fr::one(),
                beta_response: Fr::one(),
            },
        };
        let mut hostile_artifact = encode_artifact(&artifact).unwrap();
        hostile_artifact[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            decode_artifact(&hostile_artifact),
            Err(CeremonyError::InvalidContribution)
        );
    }

    #[test]
    #[ignore = "production-size algebraic integration; run explicitly for release evidence"]
    fn production_specialization_matches_real_prover_and_all_public_inputs() {
        let fingerprint = circuit_fingerprint().unwrap();
        let mut rng = StdRng::seed_from_u64(0x5048_4153_4531);
        let phase1 = known_accumulator(
            2 * fingerprint.domain_size - 1,
            Fr::from(5u64),
            Fr::from(7u64),
            Fr::from(11u64),
        );
        let specialized = specialize(&phase1).unwrap();
        let encoded = crate::ceremony::encode_for_phase1_test(&specialized).unwrap();
        let final_key = crate::ceremony::contribute(&encoded, &mut rng).unwrap();
        let (checked, _, _) = crate::ceremony::validate_final_key(&final_key, &mut rng).unwrap();
        assert_eq!(checked, fingerprint);
    }
}
