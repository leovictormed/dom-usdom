//! Dependency-minimal canonical framing shared by USDOM RPC clients and nodes.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use thiserror::Error;

const CANDIDATE_ID_TAG_V1: &str = "DOM:usdom-v2-mining-candidate:v1";

/// Exact request magic and schema identity for candidate-V2 submission.
pub const USDOM_V2_CANDIDATE_RPC_MAGIC_V1: [u8; 8] = *b"UDV2RPC1";
/// Bytes preceding the two opaque candidate components.
pub const USDOM_V2_CANDIDATE_RPC_HEADER_BYTES_V1: usize = 16;
/// Maximum proof-envelope bytes accepted by the candidate-V2 protocol.
pub const MAX_USDOM_V2_CANDIDATE_ENVELOPE_BYTES_V1: usize = 8 * 1_024 * 1_024;
/// Maximum ordered execution-witness bytes accepted by candidate-V2.
pub const MAX_USDOM_V2_CANDIDATE_WITNESS_BYTES_V1: usize = 4 * 1_024 * 1_024;
/// Exact maximum framed request size.
pub const MAX_USDOM_V2_CANDIDATE_RPC_BODY_BYTES_V1: usize = USDOM_V2_CANDIDATE_RPC_HEADER_BYTES_V1
    + MAX_USDOM_V2_CANDIDATE_ENVELOPE_BYTES_V1
    + MAX_USDOM_V2_CANDIDATE_WITNESS_BYTES_V1;

/// Invalid or noncanonical candidate-V2 request framing.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSubmissionCodecError {
    /// Either opaque component was empty.
    #[error("native USDOM V2 envelope and witnesses must not be empty")]
    EmptyComponent,
    /// The proof envelope exceeded its independent consensus ceiling.
    #[error("native USDOM V2 envelope exceeds its byte limit")]
    EnvelopeTooLarge,
    /// The execution witness bundle exceeded its independent consensus ceiling.
    #[error("native USDOM V2 witnesses exceed their byte limit")]
    WitnessesTooLarge,
    /// A component length did not fit the fixed-width framing.
    #[error("native USDOM V2 component length overflow")]
    LengthOverflow,
    /// Magic, lengths, total size, truncation, or trailing bytes were invalid.
    #[error("invalid native USDOM V2 candidate RPC framing")]
    InvalidFraming,
}

/// Borrowed exact components recovered from one canonical request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateSubmissionV1<'a> {
    envelope: &'a [u8],
    witnesses: &'a [u8],
}

impl<'a> CandidateSubmissionV1<'a> {
    /// Canonical proof-envelope bytes.
    pub fn envelope(self) -> &'a [u8] {
        self.envelope
    }

    /// Canonical ordered execution-witness bytes.
    pub fn witnesses(self) -> &'a [u8] {
        self.witnesses
    }
}

/// Encode one canonical candidate-V2 submission request.
pub fn encode_candidate_submission_v1(
    envelope: &[u8],
    witnesses: &[u8],
) -> Result<Vec<u8>, CandidateSubmissionCodecError> {
    validate_component_lengths(envelope.len(), witnesses.len())?;
    let envelope_len =
        u32::try_from(envelope.len()).map_err(|_| CandidateSubmissionCodecError::LengthOverflow)?;
    let witnesses_len = u32::try_from(witnesses.len())
        .map_err(|_| CandidateSubmissionCodecError::LengthOverflow)?;
    let total = USDOM_V2_CANDIDATE_RPC_HEADER_BYTES_V1
        .checked_add(envelope.len())
        .and_then(|value| value.checked_add(witnesses.len()))
        .ok_or(CandidateSubmissionCodecError::LengthOverflow)?;
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(&USDOM_V2_CANDIDATE_RPC_MAGIC_V1);
    encoded.extend_from_slice(&envelope_len.to_le_bytes());
    encoded.extend_from_slice(&witnesses_len.to_le_bytes());
    encoded.extend_from_slice(envelope);
    encoded.extend_from_slice(witnesses);
    Ok(encoded)
}

/// Decode one exact, trailing-byte-free candidate-V2 request without copying.
pub fn decode_candidate_submission_v1(
    body: &[u8],
) -> Result<CandidateSubmissionV1<'_>, CandidateSubmissionCodecError> {
    if body.len() < USDOM_V2_CANDIDATE_RPC_HEADER_BYTES_V1
        || body[..8] != USDOM_V2_CANDIDATE_RPC_MAGIC_V1
    {
        return Err(CandidateSubmissionCodecError::InvalidFraming);
    }
    let envelope_len = usize::try_from(u32::from_le_bytes(
        body[8..12]
            .try_into()
            .map_err(|_| CandidateSubmissionCodecError::InvalidFraming)?,
    ))
    .map_err(|_| CandidateSubmissionCodecError::LengthOverflow)?;
    let witnesses_len = usize::try_from(u32::from_le_bytes(
        body[12..16]
            .try_into()
            .map_err(|_| CandidateSubmissionCodecError::InvalidFraming)?,
    ))
    .map_err(|_| CandidateSubmissionCodecError::LengthOverflow)?;
    validate_component_lengths(envelope_len, witnesses_len)?;
    let expected = USDOM_V2_CANDIDATE_RPC_HEADER_BYTES_V1
        .checked_add(envelope_len)
        .and_then(|value| value.checked_add(witnesses_len))
        .ok_or(CandidateSubmissionCodecError::LengthOverflow)?;
    if expected != body.len() || expected > MAX_USDOM_V2_CANDIDATE_RPC_BODY_BYTES_V1 {
        return Err(CandidateSubmissionCodecError::InvalidFraming);
    }
    let split = USDOM_V2_CANDIDATE_RPC_HEADER_BYTES_V1 + envelope_len;
    Ok(CandidateSubmissionV1 {
        envelope: &body[USDOM_V2_CANDIDATE_RPC_HEADER_BYTES_V1..split],
        witnesses: &body[split..expected],
    })
}

/// Derive the domain-separated identifier of one exact candidate pair.
/// Lengths use the runtime's canonical big-endian identity encoding and are
/// independent of the little-endian HTTP framing lengths.
pub fn candidate_id_v1(
    envelope: &[u8],
    witnesses: &[u8],
) -> Result<[u8; 32], CandidateSubmissionCodecError> {
    validate_component_lengths(envelope.len(), witnesses.len())?;
    let envelope_len =
        u32::try_from(envelope.len()).map_err(|_| CandidateSubmissionCodecError::LengthOverflow)?;
    let witnesses_len = u32::try_from(witnesses.len())
        .map_err(|_| CandidateSubmissionCodecError::LengthOverflow)?;
    let capacity = 8usize
        .checked_add(envelope.len())
        .and_then(|value| value.checked_add(witnesses.len()))
        .ok_or(CandidateSubmissionCodecError::LengthOverflow)?;
    let mut identity = Vec::with_capacity(capacity);
    identity.extend_from_slice(&envelope_len.to_be_bytes());
    identity.extend_from_slice(envelope);
    identity.extend_from_slice(&witnesses_len.to_be_bytes());
    identity.extend_from_slice(witnesses);
    Ok(*dom_crypto::hash::blake2b_256_tagged(CANDIDATE_ID_TAG_V1, &identity).as_bytes())
}

fn validate_component_lengths(
    envelope_len: usize,
    witnesses_len: usize,
) -> Result<(), CandidateSubmissionCodecError> {
    if envelope_len == 0 || witnesses_len == 0 {
        return Err(CandidateSubmissionCodecError::EmptyComponent);
    }
    if envelope_len > MAX_USDOM_V2_CANDIDATE_ENVELOPE_BYTES_V1 {
        return Err(CandidateSubmissionCodecError::EnvelopeTooLarge);
    }
    if witnesses_len > MAX_USDOM_V2_CANDIDATE_WITNESS_BYTES_V1 {
        return Err(CandidateSubmissionCodecError::WitnessesTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_roundtrip_and_every_framing_mutation_fail_closed() {
        let encoded = encode_candidate_submission_v1(&[1, 2, 3], &[4, 5]).unwrap();
        let decoded = decode_candidate_submission_v1(&encoded).unwrap();
        assert_eq!(decoded.envelope(), [1, 2, 3]);
        assert_eq!(decoded.witnesses(), [4, 5]);
        let candidate_id = candidate_id_v1(decoded.envelope(), decoded.witnesses()).unwrap();
        assert_ne!(candidate_id, [0; 32]);
        assert_ne!(candidate_id, candidate_id_v1(&[1, 2], &[3, 4, 5]).unwrap());

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        let mut zero_envelope = encoded.clone();
        zero_envelope[8..12].copy_from_slice(&0u32.to_le_bytes());
        let mut zero_witnesses = encoded.clone();
        zero_witnesses[12..16].copy_from_slice(&0u32.to_le_bytes());
        let mut trailing = encoded.clone();
        trailing.push(0);
        for invalid in [
            bad_magic,
            zero_envelope,
            zero_witnesses,
            trailing,
            encoded[..encoded.len() - 1].to_vec(),
        ] {
            assert!(decode_candidate_submission_v1(&invalid).is_err());
        }
    }

    #[test]
    fn independent_component_ceilings_are_enforced() {
        assert_eq!(
            encode_candidate_submission_v1(&[], &[1]).unwrap_err(),
            CandidateSubmissionCodecError::EmptyComponent
        );
        assert_eq!(
            encode_candidate_submission_v1(&[1], &[]).unwrap_err(),
            CandidateSubmissionCodecError::EmptyComponent
        );
        assert_eq!(
            encode_candidate_submission_v1(
                &vec![1; MAX_USDOM_V2_CANDIDATE_ENVELOPE_BYTES_V1 + 1],
                &[1]
            )
            .unwrap_err(),
            CandidateSubmissionCodecError::EnvelopeTooLarge
        );
        assert_eq!(
            encode_candidate_submission_v1(
                &[1],
                &vec![1; MAX_USDOM_V2_CANDIDATE_WITNESS_BYTES_V1 + 1]
            )
            .unwrap_err(),
            CandidateSubmissionCodecError::WitnessesTooLarge
        );
    }
}
