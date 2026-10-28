import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {RISC0_TRUSTED_SETUP_AUTHORITY_SHA256,validateRisc0TrustedSetupAuthority}
  from '../../sdk/risc0-trusted-setup-authority.mjs';

const authority=JSON.parse(await readFile(new URL('../../config/risc0-trusted-setup-authority-v1.json',import.meta.url),'utf8'));

test('reviewed ceremony authority bytes match the source-pinned immutable identity',async()=>{
  const bytes=await readFile(new URL('../../config/risc0-trusted-setup-authority-v1.json',import.meta.url));
  assert.equal(createHash('sha256').update(bytes).digest('hex'),RISC0_TRUSTED_SETUP_AUTHORITY_SHA256);
});

test('RISC Zero ceremony authority pins sources and requires independent zkey verification',()=>{
  const validated=validateRisc0TrustedSetupAuthority(authority);
  assert.equal(validated.r1cs_sha256,'84d3c34b7c0eb55ad1b16b24f75e0b9de307f7b74089ea4a20a998390ee24178');
  assert.equal(validated.upstream_zkey_sha256,null);
  assert.equal(validated.powers_of_tau_blake2b512.length,128);
  assert.equal(validated.release_evidence_policy,'full-zkey-sha256-plus-snarkjs-verification-required');
});

test('ceremony authority rejects invented zkey checksums, mutable sources and schema drift',()=>{
  assert.throws(()=>validateRisc0TrustedSetupAuthority({...authority,upstream_zkey_sha256:'00'.repeat(32)}),/must not/);
  assert.throws(()=>validateRisc0TrustedSetupAuthority({...authority,documentation_url:'https://raw.githubusercontent.com/risc0/risc0/main/website/api/trusted-setup-ceremony.md'}),/pinned/);
  assert.throws(()=>validateRisc0TrustedSetupAuthority({...authority,zkey_url:'https://example.com/stark_verify_final.zkey'}),/approved/);
  assert.throws(()=>validateRisc0TrustedSetupAuthority({...authority,zkey_url:'https://evilrisczero.net/stark_verify_final.zkey'}),/approved/);
  assert.throws(()=>validateRisc0TrustedSetupAuthority({...authority,powers_of_tau_blake2b512:'00'.repeat(64)}),/differs|invalid|authority/);
  assert.throws(()=>validateRisc0TrustedSetupAuthority({...authority,extra:true}),/exact/);
});
