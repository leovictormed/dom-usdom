#!/usr/bin/env python3
from pathlib import Path

repo = Path(__file__).resolve().parents[3]
lab = repo / 'labs/usdom-reserve'
materializer = (lab / 'scripts/prepare-production-release-core-materialization.mjs').read_text()
readiness = (lab / 'sdk/mainnet-readiness.mjs').read_text()
compiled = (lab / 'sdk/compiled-runtime.mjs').read_text()
burn_host = (repo / 'crates/dom-usdom-finalized-burn-proof-host/src/lib.rs').read_text()
checkpoint_host = (repo / 'crates/dom-usdom-checkpoint-proof-host/src/lib.rs').read_text()

assert "'verifyingKeySha256','trustedSetupTranscriptSha256'" in materializer
assert "'verifyingKeySha256','trustedSetupTranscriptSha256'" in readiness
assert "imageIdField:'finalizedBurnGuestImageId'" in compiled
assert "imageIdField:'checkpointGuestImageId'" in compiled
for text in (burn_host, checkpoint_host):
    assert 'verifier_parameters.as_bytes()' in text
    assert 'receipt.journal.bytes.as_slice()' in text
    assert '.verify(Risc0Digest::from(image_id))' in text
    assert 'GROTH16_VERIFIER_PARAMETERS' in text
for adapter in ('DOMFinalizedBurnRiscZeroVerifier.sol','DOMCheckpointRiscZeroVerifier.sol'):
    text = (lab / 'contracts' / adapter).read_text()
    assert 'bytes32 public immutable imageId' in text
    assert 'abi.encodeCall(IRiscZeroVerifierV3.verify, (proof, imageId, digest))' in text
print('risc0-image-vk-setup-authority: PASS')
