#!/usr/bin/env node
import {createHash} from 'node:crypto';import path from 'node:path';import {fileURLToPath} from 'node:url';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';import {deriveFinalizedBurnVerifierArtifactBinding} from '../sdk/compiled-runtime.mjs';
import {validateFinalizedBurnRecursiveCompletion} from '../sdk/finalized-burn-recursive-completion.mjs';import {writePrivateFileDurableNewOrEqual} from '../sdk/durable-private-file.mjs';
import {buildAuthenticatedFinalizedBurnSubmission,proofReserveConfigurationFromRelease} from '../sdk/finalized-burn-submission.mjs';
import {readDirectProjectFile} from '../sdk/direct-project-file.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),sha=b=>createHash('sha256').update(b).digest('hex');
if(process.argv.length!==2)throw new Error('fixed finalized-burn completion materializer accepts no arguments');
const rel={outerIndex:'evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt-set-index.json',outerReceipt:'evidence/checkpoint-outer-receipt-set/checkpoint-outer-receipt.bin',
 receiptIndex:'evidence/finalized-burn-receipt/finalized-burn-receipt-index.json',receipt:'evidence/finalized-burn-receipt/finalized-burn-receipt.bin',proofIndex:'evidence/finalized-burn-evm-proof/finalized-burn-evm-proof-index.json',
 sourceIndex:'evidence/finalized-burn-source/finalized-burn-source-index.json',sourceInput:'evidence/finalized-burn-source/finalized-burn-input.bin',evmSeal:'evidence/finalized-burn-evm-proof/finalized-burn-evm-seal.bin',groth16Receipt:'evidence/finalized-burn-evm-proof/finalized-burn-groth16-receipt.bin',release:'config/proof-reserve.unconfigured.json',
 artifact:'out/DOMFinalizedBurnRiscZeroVerifier.sol/DOMFinalizedBurnRiscZeroVerifier.json',config:'config/finalized-burn-verifier.unconfigured.json'};
const bytes={};for(const [k,v] of Object.entries(rel))bytes[k]=await readDirectProjectFile(root,v);
const outer=parseStrictJsonBytes(bytes.outerIndex,{label:'outer receipt index',maxBytes:4*1024*1024,maxDepth:32}),receipt=parseStrictJsonBytes(bytes.receiptIndex,{label:'burn receipt index',maxBytes:1024*1024,maxDepth:16}),proof=parseStrictJsonBytes(bytes.proofIndex,{label:'burn proof index',maxBytes:1024*1024,maxDepth:16});
if(outer.outer_receipt_verified!==true||outer.dev_mode!==false||receipt.receipt_verified!==true||receipt.dev_mode!==false||proof.receipt_verified!==true||proof.dev_mode!==false)throw new Error('recursive receipt graph is not positively verified');
if(outer.receipt_file!=='checkpoint-outer-receipt.bin'||outer.receipt_sha256!==sha(bytes.outerReceipt))throw new Error('outer receipt differs from its verified index');
if(receipt.receipt_file!=='finalized-burn-receipt.bin'||receipt.receipt_sha256!==sha(bytes.receipt))throw new Error('finalized-burn receipt differs from its verified index');
if(proof.groth16_receipt_file!=='finalized-burn-groth16-receipt.bin'
    ||proof.groth16_receipt_sha256!==sha(bytes.groth16Receipt)
    ||proof.groth16_receipt_bytes!==bytes.groth16Receipt.length) {
  throw new Error('finalized-burn Groth16 receipt differs from its EVM proof index');
}
const artifact=parseStrictJsonBytes(bytes.artifact,{label:'adapter artifact',maxBytes:16*1024*1024,maxDepth:64}),config=parseStrictJsonBytes(bytes.config,{label:'verifier config',maxBytes:4*1024*1024,maxDepth:32}),release=parseStrictJsonBytes(bytes.release,{label:'reserve release',maxBytes:4*1024*1024,maxDepth:32});const sources={};for(const p of Object.keys(artifact.metadata.sources).sort())sources[p]=(await readDirectProjectFile(root,p)).toString('utf8');
const binding=deriveFinalizedBurnVerifierArtifactBinding({artifact,verifierConfig:config,sourceContents:sources,expectedConfigHash:config.verifierConfigHash});
buildAuthenticatedFinalizedBurnSubmission({reserveConfiguration:proofReserveConfigurationFromRelease(release),verifierConfiguration:config,sourceIndex:bytes.sourceIndex,sourceInput:bytes.sourceInput,receiptIndex:bytes.receiptIndex,proofIndex:bytes.proofIndex,evmSeal:bytes.evmSeal,releaseConfigSha256:sha(bytes.release)});
const authority={checkpointOuterReceipt:bytes.outerReceipt,checkpointOuterReceiptIndex:bytes.outerIndex,
 finalizedBurnReceipt:bytes.receipt,finalizedBurnReceiptIndex:bytes.receiptIndex,
 finalizedBurnProofIndex:bytes.proofIndex,finalizedBurnSourceIndex:bytes.sourceIndex,
 finalizedBurnSourceInput:bytes.sourceInput,finalizedBurnEvmSeal:bytes.evmSeal,
 finalizedBurnGroth16Receipt:bytes.groth16Receipt,releaseConfig:bytes.release,verifierConfig:bytes.config};
const candidate={schema:'usdom-finalized-burn-recursive-completion/v3',checkpointOuterReceiptSha256:sha(bytes.outerReceipt),checkpointOuterReceiptIndexSha256:sha(bytes.outerIndex),checkpointOuterReceiptVerified:true,finalizedBurnReceiptSha256:sha(bytes.receipt),finalizedBurnReceiptIndexSha256:sha(bytes.receiptIndex),finalizedBurnReceiptVerified:true,finalizedBurnProofIndexSha256:sha(bytes.proofIndex),finalizedBurnSourceIndexSha256:sha(bytes.sourceIndex),finalizedBurnSourceInputSha256:sha(bytes.sourceInput),finalizedBurnEvmSealSha256:sha(bytes.evmSeal),finalizedBurnGroth16ReceiptSha256:sha(bytes.groth16Receipt),releaseConfigSha256:sha(bytes.release),verifierConfigSha256:sha(bytes.config),evmReceiptVerified:true,adapterRuntimeCodeHash:binding.runtimeCodeHash,adapterInitcodeHash:binding.initcodeHash,adapterConfigHash:binding.verifierConfigHash};
authority.completionBytes=Buffer.from(`${JSON.stringify(candidate)}\n`);
const report=validateFinalizedBurnRecursiveCompletion(candidate,authority);
const target=process.env.USDOM_FINALIZED_BURN_RECURSIVE_COMPLETION;
if(typeof target!=='string'||!path.isAbsolute(target)) {
  throw new Error('completion report path must be absolute');
}
await writePrivateFileDurableNewOrEqual(target,Buffer.from(JSON.stringify(report)+'\n'),{maximum:64*1024});
for(const [key,relative] of Object.entries(rel)) if(!(await readDirectProjectFile(root,relative)).equals(bytes[key])) {
  throw new Error(`finalized-burn recursive input changed during materialization: ${relative}`);
}
for(const [relative,snapshot] of Object.entries(sources)) if((await readDirectProjectFile(root,relative)).toString('utf8')!==snapshot) {
  throw new Error(`finalized-burn adapter source changed during materialization: ${relative}`);
}
process.stdout.write(`${JSON.stringify({schema:report.schema,path:target})}\n`);
