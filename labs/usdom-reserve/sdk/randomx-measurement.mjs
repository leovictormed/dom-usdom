import {createHash} from 'node:crypto';
import {concat,getBytes,keccak256,toUtf8Bytes} from 'ethers';
import {blake2b} from '@noble/hashes/blake2b';

export const RANDOMX_MEASUREMENT_IDENTITY=Object.freeze({
  statementSchema:'UDCRXST1',
  statementBytes:384,
  userElfSha256:'1a8e491304763477094da84ff0701ea18d935600a3b3a79eb1c1250facd6903f',
  programBinarySha256:'0601bf022575b060edaeb0b32414b2f53e72f39d2284028069099414653591dd',
  imageId:'8efa49d4fe0f616840013adb1d3029ef71642099cb336c577a2691f7eea1dc24',
  journalDomain:'DOM:checkpoint-randomx-statement:v1',
});

function fail(message) { throw new Error(message); }
function nonzero(bytes) { return bytes.some(value=>value!==0); }
function equal(left,right) { return Buffer.from(left).equals(Buffer.from(right)); }
function canonicalHex(value) { return typeof value==='string' && /^0x[0-9a-f]{64}$/.test(value); }
function domainCommitment(domain,value) {
  return keccak256(concat([toUtf8Bytes(domain),getBytes(value)]));
}

function compactTarget(bits) {
  const exponent=bits>>>24;
  const mantissa=bits&0x007fffff;
  if(mantissa===0) return new Uint8Array(32);
  if((bits&0x00800000)!==0 || exponent>32) fail('statement compact target is invalid');
  const target=new Uint8Array(32);
  const write=(position,value)=>{ if(position<32) target[31-position]=value; };
  if(exponent>=1) write(exponent-1,mantissa&0xff);
  if(exponent>=2) write(exponent-2,(mantissa>>>8)&0xff);
  if(exponent>=3) write(exponent-3,(mantissa>>>16)&0xff);
  const minimum=new Uint8Array(32); minimum[26]=0xff; minimum[27]=0xff;
  const maximum=new Uint8Array(32).fill(0xff); maximum[0]=0; maximum[1]=0xff;
  if(Buffer.compare(target,minimum)<0 || Buffer.compare(target,maximum)>0) {
    fail('statement compact target is outside consensus bounds');
  }
  return target;
}

export function inspectCanonicalRandomxStatement(value) {
  const bytes=Buffer.from(value);
  if(bytes.length!==RANDOMX_MEASUREMENT_IDENTITY.statementBytes) {
    fail('statement must contain exactly 384 bytes');
  }
  if(bytes.subarray(0,8).toString('ascii')!=='UDCRXST1'
      || bytes.readUInt16BE(8)!==1 || bytes.readUInt16BE(10)!==1) {
    fail('statement framing or version is invalid');
  }
  const networkMagic=bytes.readUInt32BE(12);
  const chainId=bytes.subarray(16,48);
  const blockHeight=bytes.readBigUInt64BE(48);
  const seedHeight=bytes.readBigUInt64BE(56);
  const seedHash=bytes.subarray(64,96);
  const preimage=bytes.subarray(96,320);
  const randomxHash=bytes.subarray(320,352);
  const target=bytes.subarray(352,384);
  const expectedSeedHeight=blockHeight<2048n?0n:(blockHeight/2048n)*2048n-64n;
  if(networkMagic===0 || !nonzero(chainId) || blockHeight===0n || !nonzero(seedHash)
      || !nonzero(randomxHash) || !nonzero(target)) fail('statement identity is zero');
  if(preimage.readUInt32LE(0)!==4 || preimage.readBigUInt64LE(36)!==blockHeight
      || seedHeight!==expectedSeedHeight || seedHeight>=blockHeight) {
    fail('statement height, version or seed schedule is invalid');
  }
  const expanded=compactTarget(preimage.readUInt32LE(180));
  if(!equal(expanded,target)) fail('statement target does not match its PoW preimage');
  if(Buffer.compare(randomxHash,target)>0) fail('statement RandomX hash is above target');
  const statementSha256=createHash('sha256').update(bytes).digest('hex');
  const journal=keccak256(concat([
    toUtf8Bytes(RANDOMX_MEASUREMENT_IDENTITY.journalDomain),getBytes(bytes),
  ]));
  return {
    statementSha256,
    journal,
    networkMagic:String(networkMagic),
    blockHeight:blockHeight.toString(),
    seedHeight:seedHeight.toString(),
    compactTarget:`0x${preimage.readUInt32LE(180).toString(16).padStart(8,'0')}`,
  };
}

const EXPORT_KEYS=[
  'blockHash','blockHeight','generatesProof','mines','nativeOpeningCommitment',
  'policyInputCommitment','portableSegmentExecuted','privateInputCommitment','randomxRelationExecuted',
  'reportPath','schema','selectedBlockIndex','sourceBlockCount','statementCommitment','statementPath',
  'transitionCommitment',
].sort();

function terminalPackageHeader(privateInput,expectedCount) {
  const bytes=Buffer.from(privateInput);
  if(bytes.length<12 || bytes.subarray(0,8).toString('ascii')!=='UDCSPI01'
      || bytes.readUInt16BE(8)!==1 || bytes.readUInt16BE(10)!==expectedCount) {
    fail('authenticated export private input framing is invalid');
  }
  let cursor=12;
  let terminal=null;
  for(let index=0;index<expectedCount;index++) {
    if(cursor+12>bytes.length) fail('authenticated export private input is truncated');
    const packageLength=bytes.readUInt32BE(cursor);
    const nativeLength=bytes.readUInt32BE(cursor+4);
    const economicLength=bytes.readUInt32BE(cursor+8);
    const packageStart=cursor+12;
    const packageEnd=packageStart+packageLength;
    const nativeEnd=packageEnd+nativeLength;
    const economicEnd=nativeEnd+economicLength;
    if(packageLength===0 || nativeLength===0 || economicLength===0
        || economicEnd>bytes.length || !Number.isSafeInteger(economicEnd)) {
      fail('authenticated export private input component lengths are invalid');
    }
    terminal=bytes.subarray(packageStart,packageEnd);
    cursor=economicEnd;
  }
  if(cursor!==bytes.length || terminal===null || terminal.length<18+256
      || terminal.subarray(0,8).toString('ascii')!=='USDOMBL4'
      || terminal.readUInt16BE(8)!==1) {
    fail('authenticated export terminal package framing is invalid');
  }
  const blockLength=terminal.readUInt32BE(10);
  const proofLength=terminal.readUInt32BE(14);
  if(blockLength<256 || 18+blockLength+proofLength!==terminal.length) {
    fail('authenticated export terminal package lengths are invalid');
  }
  return terminal.subarray(18,18+256);
}

export function inspectAuthenticatedRandomxExport(report,sources,statementValue) {
  if(report===null || typeof report!=='object' || Array.isArray(report)
      || JSON.stringify(Object.keys(report).sort())!==JSON.stringify(EXPORT_KEYS)) {
    fail('authenticated export report schema is invalid');
  }
  if(report.schema!=='usdom-authenticated-randomx-statement-export-v1'
      || report.portableSegmentExecuted!==true || report.randomxRelationExecuted!==false
      || report.generatesProof!==false || report.mines!==false
      || report.statementPath!=='evidence/randomx-canonical-statement.bin'
      || report.reportPath!=='evidence/randomx-canonical-statement-export.json'
      || !Number.isSafeInteger(report.sourceBlockCount) || report.sourceBlockCount<1
      || report.sourceBlockCount>32 || report.selectedBlockIndex!==report.sourceBlockCount-1
      || !/^[1-9][0-9]*$/.test(report.blockHeight)
      || !canonicalHex(report.blockHash) || /^0x0{64}$/.test(report.blockHash)) {
    fail('authenticated export report values are invalid');
  }
  for(const key of ['transitionCommitment','privateInputCommitment','policyInputCommitment',
    'nativeOpeningCommitment','statementCommitment']) {
    if(!canonicalHex(report[key]) || /^0x0{64}$/.test(report[key])) {
      fail(`authenticated export ${key} is invalid`);
    }
  }
  const required=['transition','privateInput','policyInput','nativeOpening'];
  if(sources===null || typeof sources!=='object' || Array.isArray(sources)
      || JSON.stringify(Object.keys(sources).sort())!==JSON.stringify(required.sort())) {
    fail('authenticated export source set is invalid');
  }
  const transition=Buffer.from(sources.transition);
  if(transition.length!==2320 || transition.subarray(0,8).toString('ascii')!=='UDCSTN04'
      || transition.readUInt16BE(8)!==4
      || transition.readUInt16BE(10)!==report.sourceBlockCount) {
    fail('authenticated export transition framing is invalid');
  }
  const economic=[44,60,76,92].map(offset=>BigInt(`0x${transition.subarray(offset,offset+16).toString('hex')}`));
  const [previousIssued,previousBurned,newIssued,newBurned]=economic;
  if(previousBurned>previousIssued || newBurned>newIssued
      || newIssued<previousIssued || newBurned<previousBurned
      || transition[108]>1 || transition[109]>1
      || (transition[108]===1 && transition[109]!==1)) {
    fail('authenticated export transition economics are invalid');
  }
  const commitments={
    transition:domainCommitment('DOM:checkpoint-segment-transition:v4',transition),
    privateInput:domainCommitment('DOM:checkpoint-segment-private-input:v1',sources.privateInput),
    policyInput:domainCommitment('DOM:checkpoint-segment-policy-input:v1',sources.policyInput),
    nativeOpening:domainCommitment('DOM:checkpoint-segment-native-state-opening:v1',sources.nativeOpening),
  };
  if(commitments.transition!==report.transitionCommitment
      || commitments.privateInput!==report.privateInputCommitment
      || commitments.policyInput!==report.policyInputCommitment
      || commitments.nativeOpening!==report.nativeOpeningCommitment
      || `0x${transition.subarray(12,44).toString('hex')}`!==report.privateInputCommitment) {
    fail('authenticated export source commitment mismatch');
  }
  const statement=Buffer.from(statementValue);
  const inspected=inspectCanonicalRandomxStatement(statement);
  if(inspected.journal!==report.statementCommitment || inspected.blockHeight!==report.blockHeight) {
    fail('authenticated export statement commitment mismatch');
  }
  const packageHeader=terminalPackageHeader(sources.privateInput,report.sourceBlockCount);
  const preimage=statement.subarray(96,320);
  const reconstructed=Buffer.alloc(256);
  preimage.copy(reconstructed,0,0,4);
  preimage.copy(reconstructed,12,4,36);
  preimage.copy(reconstructed,4,36,44);
  preimage.copy(reconstructed,44,44,224);
  statement.copy(reconstructed,224,320,352);
  if(!equal(reconstructed,packageHeader)) fail('authenticated export statement is not terminal header');
  const blockHash=`0x${Buffer.from(blake2b(reconstructed,{dkLen:32})).toString('hex')}`;
  if(blockHash!==report.blockHash) fail('authenticated export block hash mismatch');
  return {...inspected,...commitments,blockHash,sourceBlockCount:report.sourceBlockCount};
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}
