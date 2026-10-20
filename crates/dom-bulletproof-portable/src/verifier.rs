//! Pure-Rust verifier for DOM's fixed two-commitment classic Bulletproof.

use crate::{bulletproof_generator_point, point_from_sec1, PortableBulletproofError};
use k256::elliptic_curve::{ff::PrimeField, group::Group, sec1::ToEncodedPoint};
use k256::{AffinePoint, FieldElement, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

/// Exact canonical byte length of DOM's bounded two-commitment proof.
pub const BOUNDED_RANGE_PROOF_BYTES: usize = 739;
/// Largest value accepted by DOM's bounded proof construction.
pub const MAX_PROVABLE_VALUE: u64 = (1_u64 << 52) - 1;

const PROOF_NBITS: usize = 64;
const PROOF_NCOMMITS: usize = 2;
const VECTOR_LENGTH: usize = PROOF_NBITS * PROOF_NCOMMITS;
const INNER_LOG: usize = 6;
const OUTER_SCALARS_BYTES: usize = 64;
const OUTER_POINTS_OFFSET: usize = OUTER_SCALARS_BYTES;
const OUTER_POINTS_BYTES: usize = 1 + 4 * 32;
const INNER_OFFSET: usize = OUTER_POINTS_OFFSET + OUTER_POINTS_BYTES;
const INNER_DOT_OFFSET: usize = INNER_OFFSET;
const INNER_AB_OFFSET: usize = INNER_DOT_OFFSET + 32;
const INNER_LR_OFFSET: usize = INNER_AB_OFFSET + 4 * 32;
const INNER_LR_PARITY_BYTES: usize = 2;
const H_DOM_SEC1: [u8; 33] = [
    0x02, 0x0e, 0x2c, 0xfc, 0x9a, 0xba, 0x78, 0x45, 0x5f, 0xfd, 0x39, 0x0c, 0xf5, 0xf1, 0xd1, 0x7b,
    0x99, 0x82, 0xd0, 0xee, 0x29, 0xb2, 0x66, 0xbb, 0x3e, 0xa6, 0x21, 0x7b, 0x07, 0x8f, 0x09, 0xd5,
    0x50,
];

/// Verify the exact proof format accepted by DOM's native consensus backend.
///
/// `extra_commit` is empty for legacy output envelopes and contains the
/// canonical recovery capsule for wallet-V3 outputs. Malformed proofs return
/// `Ok(false)`; malformed or degenerate commitments and noncanonical proof
/// lengths return a typed error before curve arithmetic begins.
pub fn verify_bounded_range_proof(
    commitment_sec1: &[u8; 33],
    proof: &[u8],
    extra_commit: &[u8],
) -> Result<bool, PortableBulletproofError> {
    if proof.len() != BOUNDED_RANGE_PROOF_BYTES {
        return Err(PortableBulletproofError::InvalidProofLength);
    }
    let commitment = point_from_sec1(commitment_sec1)?;
    let value_generator = point_from_sec1(&H_DOM_SEC1)?;
    let complement = value_generator * Scalar::from(MAX_PROVABLE_VALUE) - commitment;
    if bool::from(complement.is_identity()) {
        return Err(PortableBulletproofError::InvalidCommitment);
    }
    Ok(verify_inner(
        [commitment, complement],
        value_generator,
        proof,
        extra_commit,
    )
    .unwrap_or(false))
}

fn verify_inner(
    commitments: [ProjectivePoint; PROOF_NCOMMITS],
    value_generator: ProjectivePoint,
    proof: &[u8],
    extra_commit: &[u8],
) -> Option<bool> {
    let a_point = packed_point(&proof[OUTER_POINTS_OFFSET..], 0, 4)?;
    let s_point = packed_point(&proof[OUTER_POINTS_OFFSET..], 1, 4)?;
    let t1_point = packed_point(&proof[OUTER_POINTS_OFFSET..], 2, 4)?;
    let t2_point = packed_point(&proof[OUTER_POINTS_OFFSET..], 3, 4)?;

    let mut transcript = [0_u8; 32];
    for commitment in commitments {
        transcript = update_commit(transcript, &commitment, &value_generator)?;
    }
    if !extra_commit.is_empty() {
        transcript = sha256_parts(&[&transcript, extra_commit]);
    }
    transcript = update_commit(transcript, &a_point, &s_point)?;
    let y = strict_scalar(&transcript)?;
    transcript = update_commit(transcript, &a_point, &s_point)?;
    let z = strict_scalar(&transcript)?;
    transcript = update_commit(transcript, &t1_point, &t2_point)?;
    let x = strict_scalar(&transcript)?;

    let y_inverse = Option::<Scalar>::from(y.invert())?;
    let mut y_inverse_n = y_inverse;
    for _ in 0..INNER_LOG {
        y_inverse_n = y_inverse_n.square();
    }
    let negative_z = -z;

    transcript = sha256_parts(&[&transcript, &proof[..OUTER_SCALARS_BYTES]]);
    let randomizer_61 = strict_scalar(&sha256_parts(&[&transcript]))?;
    let tau_x = strict_scalar(array_32(proof, 0)?)?;
    let mu = strict_scalar(array_32(proof, 32)?)?;
    let dot = scalar_allow_zero(array_32(proof, INNER_DOT_OFFSET)?)?;

    let mut ab = [Scalar::ZERO; 4];
    for (index, scalar) in ab.iter_mut().enumerate() {
        *scalar = strict_scalar(array_32(proof, INNER_AB_OFFSET + index * 32)?)?;
    }
    let ab_dot = ab[0] * ab[2] + ab[1] * ab[3];

    let p_offset = mu + tau_x * randomizer_61;
    let inner_proof = proof.get(INNER_OFFSET..)?;
    let batch_seed = sha256_parts(&[inner_proof, &transcript, &scalar_bytes(&p_offset)]);
    let batch_randomizer = strict_scalar(&sha256_parts(&[&batch_seed]))?;

    let mut inner_commit = sha256_parts(&[&transcript, array_32(proof, INNER_DOT_OFFSET)?]);
    let inner_x = strict_scalar(&inner_commit)?;
    let g_offset = (inner_x * (dot - ab_dot) + p_offset) * batch_randomizer;

    let lr_data = proof.get(INNER_LR_OFFSET..)?;
    if lr_data.len() != INNER_LR_PARITY_BYTES + 2 * INNER_LOG * 32 {
        return None;
    }
    let mut x_squares = [Scalar::ZERO; INNER_LOG];
    let mut product = batch_randomizer;
    for (level, x_square) in x_squares.iter_mut().enumerate() {
        let left = level * 2;
        let right = left + 1;
        let parity = ((packed_nonquadratic(lr_data, left)? as u8) << 1)
            | packed_nonquadratic(lr_data, right)? as u8;
        inner_commit = sha256_parts(&[
            &inner_commit,
            &[parity],
            packed_x(lr_data, left, 2 * INNER_LOG)?,
            packed_x(lr_data, right, 2 * INNER_LOG)?,
        ]);
        let challenge = strict_scalar(&inner_commit)?;
        product *= challenge;
        *x_square = challenge.square();
    }

    let mut inverses = [Scalar::ZERO; 4];
    let inverse_inputs = [ab[0], ab[1], ab[2], product];
    for index in 0..4 {
        inverses[index] = Option::<Scalar>::from(inverse_inputs[index].invert())?;
    }
    let x_inverse_mask = -inverses[0] * inverses[3];
    for index in (1..4).rev() {
        let previous = if index == 2 {
            index - 1
        } else {
            index & (index - 1)
        };
        inverses[index - 1] = inverses[previous] * ab[index];
    }
    let mut x_cache = [Scalar::ZERO; 9];
    x_cache[0] = x_inverse_mask * (batch_randomizer * ab[0]).square();
    let mut x_square_inverses = [Scalar::ZERO; INNER_LOG];
    let mut x_square_inverse_y = [Scalar::ZERO; INNER_LOG];

    let mut equation = ProjectivePoint::IDENTITY;
    let generator_offset = negative_z * batch_randomizer;
    let z_randomized = z * batch_randomizer;
    let mut range_z_square = z.square();

    for index in 0..2 * VECTOR_LENGTH {
        let cache_index = index.count_ones() as usize;
        if cache_index > 0 {
            if index % (VECTOR_LENGTH / 2) == 0 {
                let ratio_index = index / (VECTOR_LENGTH / 2) - 1;
                let previous_cache = if index == VECTOR_LENGTH {
                    let mut y_power = y_inverse;
                    for level in 0..INNER_LOG {
                        x_square_inverse_y[level] = x_square_inverses[level] * y_power;
                        y_power = y_power.square();
                    }
                    inverses[2] *= y_power;
                    (index - 1).count_ones() as usize
                } else {
                    cache_index - 1
                };
                x_cache[cache_index] = x_cache[previous_cache] * inverses[ratio_index];
            } else if index < VECTOR_LENGTH {
                let square_index = index.trailing_zeros() as usize;
                x_cache[cache_index] = x_cache[cache_index - 1] * x_squares[square_index];
            } else {
                let inverse_index = index.trailing_zeros() as usize;
                x_cache[cache_index] = x_cache[cache_index - 1] * x_square_inverse_y[inverse_index];
            }
        }
        let mut coefficient = x_cache[cache_index];
        if index < VECTOR_LENGTH / 2 && index.count_ones() as usize == INNER_LOG - 1 {
            let inverse_index = (!index).trailing_zeros() as usize;
            x_square_inverses[inverse_index] = coefficient * x_inverse_mask;
        }

        if index < VECTOR_LENGTH {
            coefficient += generator_offset;
        } else {
            let relative = index - VECTOR_LENGTH;
            let commitment_index = relative / PROOF_NBITS;
            let bit_index = relative % PROOF_NBITS;
            if bit_index == 0 {
                range_z_square = z.square();
                let step = z * y_inverse_n;
                for _ in 0..commitment_index {
                    range_z_square *= step;
                }
                range_z_square *= batch_randomizer;
            }
            coefficient += range_z_square + z_randomized;
            range_z_square *= y_inverse;
            range_z_square += range_z_square;
        }
        equation += bulletproof_generator_point(index).ok()? * coefficient;
    }

    for (level, x_square) in x_squares.iter().copied().enumerate() {
        let left = packed_point(lr_data, 2 * level, 2 * INNER_LOG)?;
        let right = packed_point(lr_data, 2 * level + 1, 2 * INNER_LOG)?;
        let inverse = Option::<Scalar>::from(x_square.invert())?;
        equation += left * (x_square * batch_randomizer);
        equation += right * (inverse * batch_randomizer);
    }

    equation += ProjectivePoint::GENERATOR * g_offset;

    let asset_coefficient = range_asset_coefficient(y, z, dot, randomizer_61, batch_randomizer);
    equation += value_generator * asset_coefficient;
    equation += a_point * batch_randomizer;
    equation += s_point * (x * batch_randomizer);
    equation += t1_point * (x * randomizer_61 * batch_randomizer);
    equation += t2_point * (x.square() * randomizer_61 * batch_randomizer);
    let mut commitment_power = z.square();
    for commitment in commitments {
        equation += commitment * (commitment_power * randomizer_61 * batch_randomizer);
        commitment_power *= z;
    }

    Some(bool::from(equation.is_identity()))
}

fn range_asset_coefficient(
    y: Scalar,
    z: Scalar,
    dot: Scalar,
    randomizer_61: Scalar,
    batch_randomizer: Scalar,
) -> Scalar {
    let mut y_sum = Scalar::ZERO;
    let mut powers_of_two_sum;
    let mut two_sum = Scalar::ZERO;
    let mut z_power = z.square();
    for _commitment in 0..PROOF_NCOMMITS {
        powers_of_two_sum = Scalar::ZERO;
        for _ in 0..PROOF_NBITS {
            y_sum *= y;
            y_sum += Scalar::ONE;
            powers_of_two_sum += powers_of_two_sum;
            powers_of_two_sum += Scalar::ONE;
        }
        z_power *= -z;
        two_sum += powers_of_two_sum * z_power;
        z_power = -z_power;
    }
    ((z - z.square()) * y_sum + two_sum - dot) * randomizer_61 * batch_randomizer
}

fn strict_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    let scalar = scalar_allow_zero(bytes)?;
    if bool::from(scalar.is_zero()) {
        None
    } else {
        Some(scalar)
    }
}

fn scalar_allow_zero(bytes: &[u8; 32]) -> Option<Scalar> {
    Option::<Scalar>::from(Scalar::from_repr((*bytes).into()))
}

fn scalar_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_repr().into()
}

fn array_32(bytes: &[u8], offset: usize) -> Option<&[u8; 32]> {
    bytes.get(offset..offset + 32)?.try_into().ok()
}

fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

fn update_commit(
    transcript: [u8; 32],
    left: &ProjectivePoint,
    right: &ProjectivePoint,
) -> Option<[u8; 32]> {
    let (left_x, left_square) = point_x_and_square(left)?;
    let (right_x, right_square) = point_x_and_square(right)?;
    let parity = ((!left_square as u8) << 1) | (!right_square as u8);
    Some(sha256_parts(&[&transcript, &[parity], &left_x, &right_x]))
}

fn point_x_and_square(point: &ProjectivePoint) -> Option<([u8; 32], bool)> {
    if bool::from(point.is_identity()) {
        return None;
    }
    let encoded = AffinePoint::from(*point).to_encoded_point(false);
    let mut x = [0_u8; 32];
    x.copy_from_slice(encoded.x()?);
    let y_bytes = encoded.y()?;
    let y = Option::<FieldElement>::from(FieldElement::from_bytes(y_bytes))?;
    Some((x, bool::from(y.sqrt().is_some())))
}

fn packed_nonquadratic(data: &[u8], index: usize) -> Option<bool> {
    let byte = *data.get(index / 8)?;
    Some(byte & (1 << (index % 8)) != 0)
}

fn packed_x(data: &[u8], index: usize, count: usize) -> Option<&[u8; 32]> {
    let parity_bytes = count.checked_add(7)? / 8;
    let start = parity_bytes.checked_add(index.checked_mul(32)?)?;
    data.get(start..start + 32)?.try_into().ok()
}

fn packed_point(data: &[u8], index: usize, count: usize) -> Option<ProjectivePoint> {
    if index >= count {
        return None;
    }
    let x = packed_x(data, index, count)?;
    let prefix = if packed_nonquadratic(data, index)? {
        0x0b
    } else {
        0x0a
    };
    let mut zkp = [0_u8; 33];
    zkp[0] = prefix;
    zkp[1..].copy_from_slice(x);
    crate::point_from_zkp(&zkp).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_layout_is_exact() {
        assert_eq!(INNER_OFFSET, 193);
        assert_eq!(INNER_LR_OFFSET, 353);
        assert_eq!(INNER_LR_PARITY_BYTES + 2 * INNER_LOG * 32, 386);
        assert_eq!(INNER_LR_OFFSET + 386, BOUNDED_RANGE_PROOF_BYTES);
        assert_eq!(VECTOR_LENGTH, 128);
    }

    #[test]
    fn noncanonical_lengths_fail_before_parsing() {
        let commitment = H_DOM_SEC1;
        assert_eq!(
            verify_bounded_range_proof(&commitment, &[], &[]),
            Err(PortableBulletproofError::InvalidProofLength)
        );
        assert_eq!(
            verify_bounded_range_proof(&commitment, &[0_u8; BOUNDED_RANGE_PROOF_BYTES - 1], &[],),
            Err(PortableBulletproofError::InvalidProofLength)
        );
    }

    #[test]
    fn canonical_garbage_fails_closed() {
        let mut commitment = H_DOM_SEC1;
        commitment[0] = 0x03;
        assert!(
            !verify_bounded_range_proof(&commitment, &[0_u8; BOUNDED_RANGE_PROOF_BYTES], &[],)
                .unwrap_or(false)
        );
    }
}
