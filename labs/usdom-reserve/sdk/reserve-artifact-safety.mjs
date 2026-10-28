import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {id,keccak256} from 'ethers';
import {parseStrictJson} from './strict-json.mjs';

const expected={
  runtimeKeccak:'0xe56a8bc29f0771c0e823d019a03b9b70bed1c02e490858e442349bc569a31e5a',
  creationKeccak:'0xe1d7a96836967634facb3577577a5fee52545d6259c67d88fb7dc956b916be00',
  functionSha256:'8680f0ca350842ec5f38e8fff4890341c8871d9c2df18e2c9a793d8407a175fc',
  eventSha256:'4e0315a67bba8b9c6aae30fb51e1d2eb39055acc3ca5cb322d59870c68edfaf0',
  errorSha256:'0fb57b1c51d526f480e6287a422bcb2e0225fce419e5faba66fca1952ea7e22c',
  methodsSha256:'d97b96fc590357a8bbbec23876e737cc1f5120e755c8964c50f76b370fceae77',
};

function fail(message) { throw new Error(message); }
function stable(value) {
  if(Array.isArray(value)) return value.map(stable);
  if(value&&typeof value==='object') return Object.fromEntries(
    Object.keys(value).sort().map(key=>[key,stable(value[key])]));
  return value;
}
function sha(lines) {
  return createHash('sha256').update(`${[...lines].sort().join('\n')}\n`).digest('hex');
}
function abiType(value) {
  if(!value.type.startsWith('tuple')) return value.type;
  return `(${value.components.map(abiType).join(',')})${value.type.slice(5)}`;
}
function signatures(abi,kind) {
  return abi.filter(item=>item.type===kind).map(item=>
    `${item.name}(${(item.inputs??[]).map(abiType).join(',')})`);
}
function immutableIds(value,result=new Set()) {
  if(Array.isArray(value)) for(const item of value) immutableIds(item,result);
  else if(value && typeof value==='object') {
    if(value.nodeType==='VariableDeclaration'&&value.mutability==='immutable') result.add(String(value.id));
    for(const child of Object.values(value)) immutableIds(child,result);
  }
  return result;
}
function bytecode(value,label) {
  if(typeof value!=='string'||!/^0x[0-9a-f]+$/.test(value)||value.length%2!==0) fail(`${label} is malformed`);
  return Buffer.from(value.slice(2),'hex');
}

export function auditReserveArtifact(artifact,{root,sourceContents}={}) {
  if(!artifact||typeof artifact!=='object'||!Array.isArray(artifact.abi)) fail('reserve artifact is malformed');
  const metadata=artifact.metadata,settings=metadata?.settings;
  if(metadata?.compiler?.version!=='0.8.37+commit.f401782d'||settings?.evmVersion!=='cancun'
      ||settings?.optimizer?.enabled!==true||settings.optimizer.runs!==1||settings?.viaIR!==true
      ||settings?.metadata?.bytecodeHash!=='none') fail('reserve toolchain metadata drifted');
  let raw;
  try { raw=parseStrictJson(artifact.rawMetadata,{label:'reserve raw metadata',maxBytes:4*1024*1024,maxDepth:128}); }
  catch { fail('reserve raw metadata is malformed'); }
  // Foundry's parsed metadata removes solc's empty remapping context prefix.
  // Normalize only that documented representation difference.
  if(Array.isArray(raw?.settings?.remappings)) {
    raw.settings.remappings=raw.settings.remappings.map(value=>value.startsWith(':')?value.slice(1):value);
  }
  for(const field of ['compiler','language','settings','sources','version']) {
    if(JSON.stringify(stable(raw[field]))!==JSON.stringify(stable(metadata[field]))) {
      fail(`reserve raw and parsed metadata differ: ${field}`);
    }
  }

  const methodSignatures=signatures(artifact.abi,'function');
  const eventSignatures=signatures(artifact.abi,'event');
  const errorSignatures=signatures(artifact.abi,'error');
  if(new Set(methodSignatures).size!==methodSignatures.length
      ||new Set(eventSignatures).size!==eventSignatures.length
      ||new Set(errorSignatures).size!==errorSignatures.length) fail('duplicate ABI signature');
  if(sha(methodSignatures)!==expected.functionSha256||sha(eventSignatures)!==expected.eventSha256
      ||sha(errorSignatures)!==expected.errorSha256) fail('reserve ABI/event/error surface drifted');
  const methods=artifact.methodIdentifiers;
  if(!methods||Object.keys(methods).length!==methodSignatures.length
      ||methodSignatures.some(signature=>methods[signature]!==id(signature).slice(2,10))) {
    fail('method identifiers do not reproduce the ABI');
  }
  if(new Set(Object.values(methods)).size!==Object.keys(methods).length) fail('function selector collision');
  if(sha(Object.entries(methods).map(([signature,selector])=>`${signature}=${selector}`))!==expected.methodsSha256) {
    fail('method identifier surface drifted');
  }
  const eventTopics=eventSignatures.map(signature=>id(signature));
  const errorSelectors=errorSignatures.map(signature=>id(signature).slice(2,10));
  if(new Set(eventTopics).size!==eventTopics.length||new Set(errorSelectors).size!==errorSelectors.length) {
    fail('event topic or error selector collision');
  }
  if(new Set([...Object.values(methods),...errorSelectors]).size!==methodSignatures.length+errorSignatures.length) {
    fail('function/error selector collision');
  }

  if(Object.keys(artifact.bytecode?.linkReferences??{}).length
      ||Object.keys(artifact.deployedBytecode?.linkReferences??{}).length) fail('linked library reference present');
  const runtime=bytecode(artifact.deployedBytecode?.object,'reserve runtime');
  const creation=bytecode(artifact.bytecode?.object,'reserve creation bytecode');
  if(runtime.length!==20_339||creation.length!==26_553) fail('canonical reserve bytecode size drifted');
  const astIds=immutableIds(artifact.ast),references=artifact.deployedBytecode?.immutableReferences;
  if(!references||[...astIds].some(value=>!(value in references))
      ||Object.keys(references).some(value=>!astIds.has(value))) fail('immutable reference set is incomplete');
  const ranges=[];
  for(const list of Object.values(references)) for(const reference of list) {
    if(!Number.isInteger(reference.start)||reference.length!==32
        ||reference.start<0||reference.start+32>runtime.length) fail('immutable reference range is invalid');
    ranges.push([reference.start,reference.start+32]);
  }
  ranges.sort((a,b)=>a[0]-b[0]);
  if(ranges.some((value,index)=>index&&value[0]<ranges[index-1][1])) fail('immutable references overlap');

  // via-IR places a non-executable constant data section after the first
  // INVALID delimiter. PUSH payloads are data as well; neither may be decoded
  // as opcodes. This avoids the common false positive from selector/hash bytes.
  let pc=0,delimiter=-1;
  const forbidden=new Map([[0xf0,'CREATE'],[0xf2,'CALLCODE'],[0xf4,'DELEGATECALL'],
    [0xf5,'CREATE2'],[0xff,'SELFDESTRUCT']]);
  while(pc<runtime.length) {
    const opcode=runtime[pc];
    if(opcode===0xfe) { delimiter=pc; break; }
    if(forbidden.has(opcode)) fail(`unexpected ${forbidden.get(opcode)} opcode at ${pc}`);
    if((opcode>=0x0c&&opcode<=0x0f)||(opcode>=0x1e&&opcode<=0x1f)
        ||(opcode>=0x21&&opcode<=0x2f)||(opcode>=0x4b&&opcode<=0x4f)
        ||(opcode>=0xa5&&opcode<=0xef)||opcode===0xf6||opcode===0xf7||opcode===0xf8
        ||opcode===0xf9||opcode===0xfb||opcode===0xfc) fail(`unexpected undefined opcode at ${pc}`);
    pc+=1+(opcode>=0x60&&opcode<=0x7f?opcode-0x5f:0);
  }
  if(delimiter<runtime.length*9/10) fail('runtime executable/data delimiter is unexpectedly early');
  // Check semantic structure before the identity pin so a forbidden opcode
  // reports its actual cause instead of being hidden behind the expected hash
  // mismatch. The hash remains the final fail-closed identity boundary.
  if(keccak256(runtime)!==expected.runtimeKeccak||keccak256(creation)!==expected.creationKeccak) {
    fail('canonical reserve bytecode identity drifted');
  }

  if(root||sourceContents) for(const [source,value] of Object.entries(metadata.sources??{})) {
    const bytes=sourceContents?.[source]??readFileSync(path.join(root,source));
    if(!Buffer.isBuffer(bytes)&&!(bytes instanceof Uint8Array)) fail(`metadata source is not bytes: ${source}`);
    if(keccak256(bytes)!==value.keccak256) fail(`metadata source hash drifted: ${source}`);
  }
  return {runtimeBytes:runtime.length,creationBytes:creation.length,executableBytes:delimiter,
    functionCount:methodSignatures.length,eventCount:eventSignatures.length,errorCount:errorSignatures.length,
    immutableReferenceCount:ranges.length,runtimeKeccak:expected.runtimeKeccak};
}
