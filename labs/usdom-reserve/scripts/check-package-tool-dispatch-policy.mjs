import {readFileSync,statSync,realpathSync} from 'node:fs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const pkg=JSON.parse(readFileSync(path.join(root,'package.json'),'utf8'));
const lock=JSON.parse(readFileSync(path.join(root,'config/mainnet-toolchain-lock.json'),'utf8'));
const prefix='./scripts/mainnet-tool-dispatcher ';
const official=new Set(['bash','node','python3','forge','forge-deep','npm','repo-exec']);
const fail=m=>{throw new Error(`package tool dispatch policy: ${m}`)};
for(const [name,command] of Object.entries(pkg.scripts)){
  const segments=command.split(/\s*(?:&&|\|\||;)\s*/u);
  if(segments.some(segment=>!segment.startsWith(prefix))) fail(`${name} has an undispatched command segment`);
  for(const segment of segments){
    const rest=segment.slice(prefix.length); const tool=rest.split(/\s+/u,1)[0];
    if(!official.has(tool)) fail(`${name} dispatches unsupported tool ${tool}`);
    const tail=rest.slice(tool.length);
    if(/(?:^|\s)(?:bash|node|python3|forge|npm)(?:\s|$)/u.test(tail)) fail(`${name} contains a nested bare executable`);
  }
}
for(const name of ['bash','node','python3','forge','npm']){
 const entries=lock.executables.filter(value=>value.name===name);
 if(entries.length!==1||!/^\/[\x20-\x7e]+$/u.test(entries[0].path)||!/[0-9a-f]{64}/u.test(entries[0].sha256)) fail(`${name} lock is absent or ambiguous`);
}
const provenance=JSON.parse(readFileSync(path.join(root,'config/mainnet-tool-dispatcher-provenance.json'),'utf8'));
const digest=target=>createHash('sha256').update(readFileSync(target)).digest('hex');
if(provenance.schema!=='dom-usdom-mainnet-tool-dispatcher-v1'
 ||provenance.compiler!=='/usr/bin/x86_64-linux-gnu-gcc-13'
 ||provenance.compilerSha256!==digest(provenance.compiler)
 ||provenance.source!=='labs/usdom-reserve/scripts/mainnet-tool-dispatcher.c'
 ||provenance.sourceSha256!==digest(path.join(root,'scripts/mainnet-tool-dispatcher.c'))
 ||provenance.artifact!=='labs/usdom-reserve/scripts/mainnet-tool-dispatcher'
 ||provenance.runtimeClosure?.npmEntrypoint!=='/usr/lib/chatgpt/resources/cua_node/lib/node_modules/npm/bin/npm-cli.js'
 ||provenance.runtimeClosure?.npmEntrypointSha256!==digest(provenance.runtimeClosure.npmEntrypoint)
 ||provenance.runtimeClosure?.npmNodeAuthority!=='config/mainnet-toolchain-lock.json#node'
 ||JSON.stringify(provenance.privatePath?.tools)!==JSON.stringify(['bash','node','npm','forge','cast','rustc','cargo','python3','jq','solc'])
 ||provenance.privatePath?.descriptorTarget!=='/proc/<dispatcher-parent-pid>/fd/<authenticated-fd>'
 ||JSON.stringify(provenance.privatePath?.fallbackDirectories)!==JSON.stringify(['/usr/bin','/bin'])) fail('dispatcher build provenance is invalid');
const binary=path.join(root,'scripts/mainnet-tool-dispatcher'); const st=statSync(binary);
if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||(st.mode&0o777)!==0o755||realpathSync(binary)!==binary) fail('dispatcher identity is unsafe');
const expected=lock.files.find(value=>value.path==='scripts/mainnet-tool-dispatcher');
const actual=digest(binary);
if(provenance.artifactSha256!==actual) fail('dispatcher artifact provenance drifted');
if(!expected||expected.sha256!==actual) fail('dispatcher binary is not byte-bound by the toolchain lock');
const elf=readFileSync(binary); if(elf.subarray(0,4).toString('hex')!=='7f454c46'||elf.includes(Buffer.from('/lib64/ld-linux'))) fail('dispatcher is not a static ELF');
console.log(`PASS: ${Object.keys(pkg.scripts).length} package scripts use the authenticated static dispatcher`);
