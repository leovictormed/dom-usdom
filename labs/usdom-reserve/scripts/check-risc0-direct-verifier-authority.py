#!/usr/bin/env python3
import json
import hashlib
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
    'trusted_setup_authority_path': 'config/risc0-trusted-setup-authority-v1.json',
    'trusted_setup_authority_sha256': 'fa3155a36f20231c57a15d8d5a4a54cb21f920c05cce3d4e9f96debb06abaa3b',
}
for key, expected in required.items():
    assert reference.get(key) == expected, f'reference {key} drift'
authority_path = root / reference['trusted_setup_authority_path']
authority_bytes = authority_path.read_bytes()
assert hashlib.sha256(authority_bytes).hexdigest() == reference['trusted_setup_authority_sha256'], \
    'trusted-setup authority content drift'
authority = json.loads(authority_bytes)
assert authority['schema'] == 'usdom-risc0-groth16-trusted-setup-authority/v1'
assert authority['r1cs_sha256'] == \
    '84d3c34b7c0eb55ad1b16b24f75e0b9de307f7b74089ea4a20a998390ee24178'
assert authority['upstream_zkey_sha256'] is None
assert authority['powers_of_tau_blake2b512'] == \
    '3063a0bd81d68711197c8820a92466d51aeac93e915f5136d74f63c394ee6d88c5e8016231ea6580bec02e25d491f319d92e77f5c7f46a9caa8f3b53c0ea544f'
assert authority['powers_of_tau_size'] == 9663759512
assert authority['release_evidence_policy'] == \
    'full-zkey-sha256-plus-snarkjs-verification-required'
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
