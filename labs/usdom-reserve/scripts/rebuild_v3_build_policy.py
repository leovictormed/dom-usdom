#!/usr/bin/env python3
"""Strict parser for the verify-only Cargo build policy and its build attestation."""
import hashlib,json,re
H64=re.compile(r'^[0-9a-f]{64}$')
ARGV=['cargo','build','--locked','--offline','--release','--no-default-features','--features','verify','--bin','dom-usdom-verify-rebuild-receipt','--package','dom-usdom-checkpoint-proof-host','--target','x86_64-unknown-linux-gnu']
POLICY_KEYS={'schema','package','binary','target','cargoVersion','cargoCommit','cargoSha256','cargoPath','rustcVersion','rustcCommit','rustcSha256','rustcPath','sourceClosureSha256','argv','requiredEnvironment','forbiddenEnvironment'}
FORBIDDEN=['CARGO_BUILD_RUSTC','CARGO_BUILD_RUSTC_WRAPPER','CARGO_ENCODED_RUSTFLAGS','RUSTC_WORKSPACE_WRAPPER','RUSTC_WRAPPER','RUSTDOCFLAGS','RUSTFLAGS']
REQUIRED_ENV={'CARGO_HOME':'/home/leonardov/.local/usdom-verify-build/cargo-home','CARGO_NET_OFFLINE':'true','HOME':'/home/leonardov','LC_ALL':'C','PATH':'/usr/bin:/bin','RISC0_DEV_MODE':'0','RUSTC':'/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc','SOURCE_DATE_EPOCH':'0','TZ':'UTC'}
def canonical_sha(value): return isinstance(value,str) and H64.fullmatch(value) is not None
def strict_json(raw):
 def pairs(items):
  value={}
  for key,item in items:
   if key in value: raise ValueError(f'duplicate JSON key: {key}')
   value[key]=item
  return value
 return json.loads(raw,object_pairs_hook=pairs)
def build_input_commitment(policy,policy_sha):
 value={'schema':'usdom-verify-rebuild-receipt-build-input-v1','policySha256':policy_sha,'sourceClosureSha256':policy['sourceClosureSha256'],'cargoSha256':policy['cargoSha256'],'rustcSha256':policy['rustcSha256'],'target':policy['target'],'package':policy['package'],'binary':policy['binary'],'argv':policy['argv'],'environment':policy['requiredEnvironment']}
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def load_policy(raw):
 policy=strict_json(raw)
 if set(policy)!=POLICY_KEYS or policy['schema']!='usdom-verify-rebuild-receipt-build-policy-v1' or policy['package']!='dom-usdom-checkpoint-proof-host' or policy['binary']!='dom-usdom-verify-rebuild-receipt' or policy['target']!='x86_64-unknown-linux-gnu' or policy['cargoPath']!='/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo' or policy['rustcPath']!='/home/leonardov/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc': raise ValueError('verify-only build policy identity is invalid')
 if policy['argv']!=ARGV or policy['requiredEnvironment']!=REQUIRED_ENV or policy['forbiddenEnvironment']!=FORBIDDEN: raise ValueError('verify-only command/environment policy is invalid')
 if not all(canonical_sha(policy[key]) for key in ('cargoSha256','rustcSha256','sourceClosureSha256')) or not re.fullmatch(r'1\.98\.0',policy['cargoVersion']) or not re.fullmatch(r'1\.98\.0',policy['rustcVersion']) or not all(re.fullmatch(r'[0-9a-f]{40}',policy[key] or '') for key in ('cargoCommit','rustcCommit')): raise ValueError('verify-only toolchain pin is invalid')
 return policy
def verify_attestation(raw,policy,policy_sha,binary_sha,binary_size):
 value=strict_json(raw);keys={'schema','policySha256','sourceClosureSha256','buildInputCommitment','cargoSha256','rustcSha256','target','argv','environment','binarySha256','binarySize'}
 hashes=('policySha256','sourceClosureSha256','buildInputCommitment','cargoSha256','rustcSha256','binarySha256')
 if set(value)!=keys or value['schema']!='usdom-verify-rebuild-receipt-build-attestation-v2' or not all(canonical_sha(value.get(key)) for key in hashes) or type(value.get('binarySize')) is not int or value['binarySize']<=0 or value['policySha256']!=policy_sha or value['binarySha256']!=binary_sha or value['binarySize']!=binary_size or type(binary_size) is not int or binary_size<=0 or value['sourceClosureSha256']!=policy['sourceClosureSha256'] or value['buildInputCommitment']!=build_input_commitment(policy,policy_sha): raise ValueError('verify-only build attestation identity is invalid')
 if value['cargoSha256']!=policy['cargoSha256'] or value['rustcSha256']!=policy['rustcSha256'] or value['target']!=policy['target'] or value['argv']!=policy['argv'] or value['environment']!=policy['requiredEnvironment']: raise ValueError('verify-only build attestation command/toolchain differs from policy')
 return value
