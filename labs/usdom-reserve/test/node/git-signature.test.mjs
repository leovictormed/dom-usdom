import test from 'node:test';
import assert from 'node:assert/strict';
import {
 isCanonicalGitSigningKeyFingerprint,isCanonicalReleaseTag,parseGitSignatureFingerprint,
} from '../../sdk/git-signature.mjs';

const subkey='A'.repeat(40);
const primary='B'.repeat(40);
const primaryV5='C'.repeat(64);
const ssh=`SHA256:${'a'.repeat(43)}`;

test('OpenPGP raw status selects the primary release-key fingerprint',()=>{
 const raw=`[GNUPG:] GOODSIG 1234 Soren Planck\n[GNUPG:] VALIDSIG ${subkey} 2026-10-20 0 4 0 1 10 00 ${primary}`;
 assert.equal(parseGitSignatureFingerprint(raw),primary);
 assert.equal(isCanonicalGitSigningKeyFingerprint(primary),true);
 assert.equal(isCanonicalGitSigningKeyFingerprint(primaryV5),true);
});

test('release tags are restricted to the USDOM semantic-version namespace',()=>{
 for(const value of ['usdom-v1.0.0','usdom-v0.1.2-rc.1','usdom-v12.34.56-beta']) {
  assert.equal(isCanonicalReleaseTag(value),true,value);
 }
 for(const value of [null,'','v1.0.0','usdom-v01.0.0','usdom-v1.0','usdom-v1.0.0+build',
  '--raw','../usdom-v1.0.0','usdom-v1.0.0^{}','usdom-v1.0.0.lock']) {
  assert.equal(isCanonicalReleaseTag(value),false,String(value));
 }
});

test('SSH verification output yields the canonical SHA-256 fingerprint',()=>{
 assert.equal(ssh.length,'SHA256:'.length+43);
 const output=`Good \"git\" signature for sorenplanck@tutamail.com with ED25519 key ${ssh}`;
 assert.equal(parseGitSignatureFingerprint(output),ssh);
 assert.equal(isCanonicalGitSigningKeyFingerprint(ssh),true);
});

test('unverified, lowercase, truncated and decorative fingerprint text is rejected',()=>{
 for(const value of [null,'',subkey.toLowerCase(),'A'.repeat(39),'A'.repeat(41),'SHA256:short']) {
  assert.equal(isCanonicalGitSigningKeyFingerprint(value),false,String(value));
 }
 assert.equal(parseGitSignatureFingerprint(`claimed fingerprint ${primary}`),null);
 assert.equal(parseGitSignatureFingerprint('[GNUPG:] BADSIG 1234 attacker'),null);
 assert.equal(parseGitSignatureFingerprint(`prefix [GNUPG:] VALIDSIG ${subkey} ${primary}`),null);
 assert.equal(parseGitSignatureFingerprint(
  `Good "git" signature for attacker with ED25519 key ${ssh} trailing-text`),null);
});
