import {stdin,stderr,argv} from 'node:process';
const pathIndex=argv.indexOf('--path');if(pathIndex<0||pathIndex+1>=argv.length)process.exit(2);const path=argv[pathIndex+1];
const privatePath=/(?:^|\/)(?:(?:\.npmrc|\.pypirc|\.netrc|credentials(?:\.json)?)|.*(?:private[-_]?input|private[-_]?witness|witness|credential|owner[-_]?auth|password|mnemonic|seed|raw[-_]?transaction).*)$/i;
const reviewableSource=/(?:\.(?:c|h|rs|js|mjs|ts|py|sh|sol|md|txt|toml|ya?ml)|(?:^|\/)Cargo\.lock)$/i.test(path);
if(privatePath.test(path)&&!reviewableSource){stderr.write('private binary path is forbidden from publication\n');process.exit(1)}
const elf=/\.elf$/i.test(path),wasm=/\.wasm$/i.test(path);
const namedPublicBinary=/(?:guest|program|artifact|receipt|seal|proving[-_]?key|verifying[-_]?key|image[-_]?id)/i.test(path)&&/\.(?:bin|dat|iid|zkey|receipt|seal)$/i.test(path);
const binary=elf||wasm||namedPublicBinary,limit=binary?512*1024*1024:8*1024*1024;let chunks=[],size=0;
for await(const chunk of stdin){
  size+=chunk.length;
  if(size>limit){stderr.write('staged blob exceeds content scan bound\n');process.exit(2)}
  // Public binaries only need their framing bytes. Text must be retained in
  // full: truncating the scan would let a secret after the retained prefix
  // enter an otherwise valid release commit.
  if(!binary)chunks.push(chunk);
  else {
    const retained=chunks[0]?.length??0;
    if(retained<4)chunks[0]=Buffer.concat([chunks[0]??Buffer.alloc(0),chunk.subarray(0,4-retained)]);
  }
}
const bytes=Buffer.concat(chunks);if(binary){if(size<4)process.exit(1);if(elf&&!bytes.subarray(0,4).equals(Buffer.from([0x7f,0x45,0x4c,0x46])))process.exit(1);if(wasm&&!bytes.subarray(0,4).equals(Buffer.from([0,0x61,0x73,0x6d])))process.exit(1);process.exit(0)}
let text;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes)}catch{stderr.write('non-UTF8 staged blob lacks an approved public binary class\n');process.exit(1)}
const pemPrefixes=['RSA ','EC ','OPENSSH ',''];const checks=[pemPrefixes.some(p=>text.includes(`-----BEGIN ${p}PRIVATE KEY-----`)),/"(?:privateKey|private_key|mnemonic|seedPhrase|seed_phrase|password|passphrase|bearer|rpcToken|rpc_token|ownerAuth|owner_auth)"\s*:\s*"(?!REDACTED|<[^>]+>|\$\{)[^"\r\n]{8,}"/i.test(text),/"(?:rawTransaction|raw_transaction|signedTransaction|signed_transaction)"\s*:\s*"0x(?:01|02|f8)[0-9a-f]{180,}"/i.test(text),/"(?:privateWitness|private_witness|privateInput|private_input|witnessBytes|witness_bytes)"\s*:\s*"(?:0x)?[0-9a-f]{64,}"/i.test(text),/^(?:AWS_SECRET_ACCESS_KEY|NPM_TOKEN|GITHUB_TOKEN|PRIVATE_KEY|RPC_TOKEN|OWNER_AUTH)\s*=\s*(?!REDACTED\s*$|<[^>]+>\s*$|["']?\$)[^\s#]{8,}\s*$/m.test(text)];if(checks.some(Boolean)){stderr.write('staged blob contains sensitive content\n');process.exit(1)}
