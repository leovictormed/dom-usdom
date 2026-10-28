import {getAddress} from 'ethers';

export const RISC0_MAINNET_REFERENCE_SCHEMA='usdom-risc0-ethereum-verifier-reference-v3';

export const PINNED_RISC0_MAINNET_V3=Object.freeze({
  schema:RISC0_MAINNET_REFERENCE_SCHEMA,
  approved_at:'2026-10-20',
  chain_id:'1',
  network:'ethereum-mainnet',
  risc0_ethereum_release:'v3.0.1',
  risc0_ethereum_release_commit:'365e7b2db4f620fa256580c27558d2623362b9ae',
  deployment_manifest_url:'https://raw.githubusercontent.com/risc0/risc0-ethereum/v3.0.1/contracts/deployment.toml',
  deployment_manifest_sha256:'08718c12bc06afb0dc8f54978e28a787bcce4d919f1c5b0c1e090015fbbd01f6',
  verifier_source_url:'https://raw.githubusercontent.com/risc0/risc0-ethereum/v3.0.1/contracts/src/groth16/RiscZeroGroth16Verifier.sol',
  verifier_source_sha256:'f24784fb625b8a82232c79f21db28f759593e29a287a4f9865cc6e78d36eb283',
  trusted_setup_authority_path:'config/risc0-trusted-setup-authority-v1.json',
  trusted_setup_authority_sha256:'fa3155a36f20231c57a15d8d5a4a54cb21f920c05cce3d4e9f96debb06abaa3b',
  verifier_name:'RiscZeroGroth16Verifier',
  verifier_version:'3.0.0',
  verifier_contract_kind:'direct-immutable-verifier',
  verifier_address:'0x2a098988600d87650Fb061FfAff08B97149Fa84D',
  verifier_selector:'0x73c457ba',
  observed_runtime_code_hash:'0xfe03c66078969d097f867351171b4639d726c8376c35022675ed44cbbcbaa720',
  router_address:'0x8EaB2D97Dfce405A1692a21b3ff3A172d593D319',
  emergency_stop_wrapper_address:'0x9F9994Eb4Cb5200198FEfb470f8b50301662e696',
  emergency_stop_wrapper_runtime_code_hash:'0x0dd0c6cdf06b60b1a88cb4602efbb5f492585a20fd61f8aa1d92468aad819963',
});

const fields=Object.freeze(Object.keys(PINNED_RISC0_MAINNET_V3));

/** Validate the repository reference against the reviewed, source-pinned
 * direct verifier identity. Updating RISC Zero requires an explicit source
 * change and a newly signed USDOM release. */
export function validateRiscZeroMainnetReference(input) {
  if(!input || typeof input!=='object' || Array.isArray(input)
      || Object.keys(input).length!==fields.length || fields.some(field=>!(field in input))) {
    throw new Error('exact pinned RISC Zero mainnet reference fields required');
  }
  for(const field of fields) {
    if(input[field]!==PINNED_RISC0_MAINNET_V3[field]) {
      throw new Error(`RISC Zero mainnet reference ${field} differs from the reviewed pin`);
    }
  }
  const direct=getAddress(input.verifier_address);
  if(direct===getAddress(input.router_address)
      || direct===getAddress(input.emergency_stop_wrapper_address)
      || getAddress(input.router_address)===getAddress(input.emergency_stop_wrapper_address)) {
    throw new Error('RISC Zero direct verifier, router and emergency-stop wrapper must be distinct');
  }
  return {...input,verifier_address:direct,router_address:getAddress(input.router_address),
    emergency_stop_wrapper_address:getAddress(input.emergency_stop_wrapper_address)};
}
