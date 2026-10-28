const sha256=/^[0-9a-f]{64}$/;
const commit=/^[0-9a-f]{40}$/;
const httpsUrl=/^https:\/\//;
const exactKeys=[
  'ceremony_config_sha256','ceremony_config_url','circuit_source_commit',
  'documentation_sha256','documentation_source_commit','documentation_url',
  'powers_of_tau_blake2b512','powers_of_tau_digest_source_sha256','powers_of_tau_digest_source_url',
  'powers_of_tau_power','powers_of_tau_size','powers_of_tau_url','proof_system','r1cs_sha256','r1cs_size','r1cs_url',
  'release_evidence_policy','risc0_library_source_sha256','risc0_library_source_url','schema',
  'stark_verify_source_sha256','stark_verify_source_url','status','upstream_zkey_sha256',
  'upstream_zkey_sha256_status','zkey_compressed_size','zkey_compressed_url','zkey_size','zkey_url',
].sort();

function fail(message){throw new Error(message);}
function exactObject(value){
  return value&&typeof value==='object'&&!Array.isArray(value)
    &&JSON.stringify(Object.keys(value).sort())===JSON.stringify(exactKeys);
}
function requirePinnedRawGithub(url,commitHash,label){
  const prefix=`https://raw.githubusercontent.com/risc0/risc0/${commitHash}/`;
  if(typeof url!=='string'||!url.startsWith(prefix)) fail(`${label} must use the pinned RISC Zero commit`);
}

export const RISC0_TRUSTED_SETUP_AUTHORITY_SCHEMA='usdom-risc0-groth16-trusted-setup-authority/v1';
export const RISC0_TRUSTED_SETUP_AUTHORITY_SHA256=
  'fa3155a36f20231c57a15d8d5a4a54cb21f920c05cce3d4e9f96debb06abaa3b';

export function validateRisc0TrustedSetupAuthority(value){
  if(!exactObject(value)) fail('exact RISC Zero trusted-setup authority fields required');
  if(value.schema!==RISC0_TRUSTED_SETUP_AUTHORITY_SCHEMA
      ||value.status!=='source-pinned-verification-required'
      ||value.proof_system!=='risc0-groth16-v3') fail('RISC Zero trusted-setup authority identity is invalid');
  for(const [name,hash] of Object.entries(value)) {
    if(name.endsWith('_sha256')&&name!=='upstream_zkey_sha256'&&!sha256.test(hash??'')) {
      fail(`${name} must be a lowercase SHA-256 digest`);
    }
  }
  if(value.powers_of_tau_blake2b512
      !=='3063a0bd81d68711197c8820a92466d51aeac93e915f5136d74f63c394ee6d88c5e8016231ea6580bec02e25d491f319d92e77f5c7f46a9caa8f3b53c0ea544f'
      ||value.powers_of_tau_digest_source_sha256
      !=='b267f3176ec78711a3f2f763b73546b61096d58e9019915e6be58db2df94bbc1') {
    fail('Powers of Tau digest differs from the pinned authority');
  }
  if(value.powers_of_tau_digest_source_url
      !=='https://raw.githubusercontent.com/iden3/snarkjs/22003fbcde78608be902520661832db7933d279e/README.md') {
    fail('Powers of Tau digest authority must be an immutable snarkjs source');
  }
  if(!commit.test(value.documentation_source_commit)||!commit.test(value.circuit_source_commit)) {
    fail('trusted-setup source commits must be exact Git commits');
  }
  requirePinnedRawGithub(value.documentation_url,value.documentation_source_commit,'documentation URL');
  for(const [name,url] of [
    ['ceremony config URL',value.ceremony_config_url],['STARK Verify source URL',value.stark_verify_source_url],
    ['RISC Zero circuit library URL',value.risc0_library_source_url],
  ]) requirePinnedRawGithub(url,value.circuit_source_commit,name);
  for(const [name,url] of [
    ['R1CS URL',value.r1cs_url],['Powers of Tau URL',value.powers_of_tau_url],
    ['zkey URL',value.zkey_url],['compressed zkey URL',value.zkey_compressed_url],
  ]) {
    let hostname='';
    try { hostname=new URL(url).hostname; } catch {}
    if(typeof url!=='string'||!httpsUrl.test(url)
        ||!(hostname==='risczero.net'||hostname.endsWith('.risczero.net')
          ||hostname==='risc0-artifacts.s3.us-west-2.amazonaws.com')) {
      fail(`${name} is not an approved RISC Zero artifact origin`);
    }
  }
  if(!Number.isSafeInteger(value.r1cs_size)||value.r1cs_size<=0
      ||!Number.isSafeInteger(value.zkey_size)||value.zkey_size<=0
      ||!Number.isSafeInteger(value.zkey_compressed_size)||value.zkey_compressed_size<=0
      ||!Number.isSafeInteger(value.powers_of_tau_size)||value.powers_of_tau_size<=0
      ||value.powers_of_tau_power!==23) fail('trusted-setup artifact size or Powers of Tau is invalid');
  if(value.upstream_zkey_sha256!==null
      ||value.upstream_zkey_sha256_status!=='not-published-by-authoritative-source') {
    fail('an unverified upstream zkey digest must not be treated as authoritative');
  }
  if(value.release_evidence_policy!=='full-zkey-sha256-plus-snarkjs-verification-required') {
    fail('release must require a full zkey digest and cryptographic transcript verification');
  }
  return structuredClone(value);
}

