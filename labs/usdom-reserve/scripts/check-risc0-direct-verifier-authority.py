#!/usr/bin/env python3
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
reference = json.loads((root / 'config/risc0-ethereum-mainnet-v3.json').read_text())
required = {
    'schema': 'usdom-risc0-ethereum-verifier-reference-v3',
    'chain_id': '1',
    'verifier_contract_kind': 'direct-immutable-verifier',
    'verifier_address': '0x2a098988600d87650Fb061FfAff08B97149Fa84D',
    'verifier_selector': '0x73c457ba',
    'verifier_version': '3.0.0',
    'observed_runtime_code_hash': '0xfe03c66078969d097f867351171b4639d726c8376c35022675ed44cbbcbaa720',
}
for key, expected in required.items():
    assert reference.get(key) == expected, f'reference {key} drift'
assert reference['verifier_address'].lower() not in {
    reference['router_address'].lower(), reference['emergency_stop_wrapper_address'].lower()
}
for relative in (
    'contracts/DOMFinalizedBurnRiscZeroVerifier.sol',
    'contracts/DOMCheckpointRiscZeroVerifier.sol',
):
    source = (root / relative).read_text().lower()
    assert 'block.chainid == 1' in source
    assert required['verifier_address'].lower() in source
    assert required['observed_runtime_code_hash'].lower() in source
    assert 'verifieraddress != mainnet_risc_zero_verifier' in source
    assert 'verifiercodehash != mainnet_risc_zero_verifier_code_hash' in source
print('risc0-direct-verifier-authority: PASS')
