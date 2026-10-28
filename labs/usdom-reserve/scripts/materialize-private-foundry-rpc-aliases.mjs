#!/usr/bin/env node
import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {matchMainnetPreflightRpcSources} from '../sdk/mainnet-preflight-rpc.mjs';

try {
  if(process.argv.length!==4) {
    throw new Error('private RPC sources and their public catalog are required');
  }
  const sources=parseStrictJsonBytes(await readDirectFile(process.argv[2],{
    minimum:2,maximum:32*1024,exactMode:0o600,label:'private RPC sources'}),{
    label:'private RPC sources',maxBytes:32*1024,maxDepth:8});
  const catalog=parseStrictJsonBytes(await readDirectFile(process.argv[3],{
    minimum:2,maximum:1024*1024,exactMode:0o644,label:'public RPC catalog'}),{
    label:'public RPC catalog',maxBytes:1024*1024,maxDepth:8});
  // The private file is deliberately mutable so credentials can rotate. Bind
  // every identity and endpoint origin back to the reviewed, public catalog
  // before exposing even aliases to Cast. This prevents a replaced 0600 file
  // from silently collapsing two-provider consensus onto attacker endpoints.
  const matched=matchMainnetPreflightRpcSources(catalog,sources);
  const urls=matched.slice(0,2).map(source=>source.url);
  // JSON string literals are valid TOML basic strings. The secret URLs enter
  // this process through a 0600 file and leave only through a 0600 stdout
  // redirect; child argv and environment contain aliases and a config path.
  process.stdout.write(`[rpc_endpoints]\nusdom_rpc_a = ${JSON.stringify(urls[0])}\nusdom_rpc_b = ${JSON.stringify(urls[1])}\n`);
} catch(error) {
  writeReleaseFailure('materialize-private-foundry-rpc-aliases',error);
  process.exitCode=1;
}
