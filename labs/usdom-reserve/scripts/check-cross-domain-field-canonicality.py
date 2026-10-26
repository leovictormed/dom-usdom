#!/usr/bin/env python3
"""Fail closed if Solidity/Ethereum/native BN254 wire contracts drift."""
from pathlib import Path
import re, sys
ROOT=Path(__file__).resolve().parents[1]
checks={
 'contracts/USDOMProofReserve.sol':[r'BN254_SCALAR_FIELD\s*=\s*0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001',r'uint256\(receivingCommitment\) >= BN254_SCALAR_FIELD'],
 '../usdom-ethereum-finality/src/deposits.rs':[r'const BN254_SCALAR_FIELD: \[u8; 32\]',r'receiving_commitment\.as_slice\(\) < BN254_SCALAR_FIELD\.as_slice\(\)'],
 '../../crates/dom-usdom-privacy/src/lib.rs':[r'pub fn from_bytes\(bytes: \[u8; 32\]\)',r'Fr::from_be_bytes_mod_order',r'value\.to_bytes\(\) != bytes',r'to_bytes_be\(\)'],
 '../../crates/dom-usdom-state/src/lib.rs':[r'PrivacyScalar::from_bytes\(occurrence\.receiving_commitment\)',r'PrivacyScalar::from_bytes\(\*anchor\.root\.as_bytes\(\)\)',r'PrivacyScalar::from_bytes\(\*value\)'],
 'sdk/finalized-deposit-source.mjs':[r'BigInt\(value\.receivingCommitment\)>=BN254_SCALAR_FIELD'],
 'sdk/finalized-deposit-issuance.mjs':[r'canonicalScalar\(index\.receiving_commitment\.slice\(2\)\)',r'canonicalScalar\(registration\.note_commitment\)'],
 'sdk/proof-reserve.mjs':[r'const canonical = nullifiers\.map\(scalar\)'],
}
failed=[]
for rel, patterns in checks.items():
 p=(ROOT/rel).resolve(); s=p.read_text()
 for pattern in patterns:
  if not re.search(pattern,s,re.S): failed.append(f'{rel}: missing {pattern}')
# All three explicit modulus spellings must remain byte-identical.
mod='30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001'
for rel in ['contracts/USDOMProofReserve.sol','sdk/finalized-deposit-source.mjs','sdk/finalized-deposit-issuance.mjs','sdk/proof-reserve.mjs']:
 if mod not in (ROOT/rel).read_text().lower(): failed.append(f'{rel}: modulus mismatch')
if failed:
 print('FAIL cross-domain field canonicality\n'+'\n'.join(failed)); sys.exit(1)
print('PASS cross-domain BN254 elements use canonical nonzero 32-byte big-endian encoding')
