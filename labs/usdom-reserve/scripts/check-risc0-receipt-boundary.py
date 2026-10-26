#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
adapters = [
    root / 'contracts/DOMFinalizedBurnRiscZeroVerifier.sol',
    root / 'contracts/DOMCheckpointRiscZeroVerifier.sol',
]
hosts = [
    root.parent.parent / 'crates/dom-usdom-finalized-burn-proof-host/src/lib.rs',
    root.parent.parent / 'crates/dom-usdom-checkpoint-proof-host/src/lib.rs',
]
e2es = [
    root / 'scripts/run-finalized-burn-release-e2e.mjs',
    root / 'scripts/run-checkpoint-capacity-e2e.mjs',
]
for path in adapters:
    text = path.read_text()
    assert 'EVM_PROOF_BYTES = 4 + 8 * 32' in text
    assert 'RISC_ZERO_GROTH16_V3_SELECTOR = 0x73c457ba' in text
    assert 'RISC_ZERO_VERIFIER_GAS_LIMIT = 4_500_000' in text
    assert 'sha256(abi.encodePacked(statementHash))' in text
    assert 'returnSize != 0' in text
    assert 'staticcall(RISC_ZERO_VERIFIER_GAS_LIMIT' in text
for path in hosts:
    text = path.read_text()
    assert 'EVM_SEAL_SELECTOR: [u8; 4] = [0x73, 0xc4, 0x57, 0xba]' in text
    assert 'EVM_SEAL_BYTES: usize = 4 + 8 * 32' in text
    assert 'groth16.verifier_parameters.as_bytes()' in text
    assert 'receipt.journal.bytes.as_slice()' in text
    assert 'evm_seal.extend_from_slice(&EVM_SEAL_SELECTOR)' in text
for path in e2es:
    text = path.read_text()
    assert "seal.length!==260" in text
    assert "hexlify(seal.subarray(0,4)).toLowerCase()!=='0x73c457ba'" in text
    assert 'adapter.RISC_ZERO_VERIFIER_GAS_LIMIT()' in text
    assert 'adapter.journalDigest(statementHash)' in text
    assert 'verifierGasLimit!==4_500_000n' in text
print('risc0-receipt-boundary: PASS')
