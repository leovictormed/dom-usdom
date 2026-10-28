import {createHash} from 'node:crypto';
import {safeJsonUint} from './safe-json-integer.mjs';
const H=/^[0-9a-f]{64}$/;
const X=/^0x[0-9a-f]{64}$/;
export function validateClosedMainnetBurnBlockReceipt(receipt,submission,index){
 if(receipt?.schema!=='usdom-closed-mainnet-private-burn-block-v1'||submission?.schema!=='usdom-closed-mainnet-private-burn-submission-v1'||index?.schema!=='usdom-closed-mainnet-private-burn-v1'
  ||receipt.transitionId!==submission.transition_id||receipt.transitionId!==index.transition_id
  ||receipt.candidateId!==submission.candidate_id||receipt.authorityBinding!==submission.authority_binding
  ||receipt.tpmNvIndex!=='0x01500020'||receipt.tpmNvIndex!==submission.tpm_nv_index
  ||receipt.authorizedSnapshotGeneration!==submission.authorized_snapshot_generation
  ||receipt.authorizedSnapshotGeneration!==index.snapshot_generation
  ||receipt.authorizedSnapshotSealSha256!==createHash('sha256').update(Buffer.from(submission.authorized_snapshot_seal,'hex')).digest('hex')
  ||!H.test(receipt.transitionId)||!H.test(receipt.candidateId)||!H.test(receipt.authorityBinding)||!H.test(receipt.authorizedSnapshotSealSha256)
  ||!Number.isSafeInteger(receipt.domNetworkMagic)||receipt.domNetworkMagic<0||!X.test(receipt.parentHash)||!X.test(receipt.blockHash)||!X.test(receipt.domChainId)||!X.test(receipt.domGenesisHash)
  ||receipt.exactlyOneBlock!==true||receipt.continuousMining!==false
  ||!/^([1-9][0-9]*|0)$/.test(receipt.parentHeight)||!/^([1-9][0-9]*|0)$/.test(receipt.blockHeight)
  ||BigInt(receipt.blockHeight)!==BigInt(receipt.parentHeight)+1n) throw new Error('burn block receipt does not bind the authorized prepared burn');
 return receipt;
}
export function closedMainnetBurnScanRequest(receipt){const blockHeight=safeJsonUint(receipt.blockHeight,'burn block height'),parentHeight=safeJsonUint(receipt.parentHeight,'burn parent height');return {schema_version:1,expected_network_magic:receipt.domNetworkMagic,expected_chain_id:receipt.domChainId.slice(2),transition_id:receipt.transitionId,start_height:blockHeight,max_blocks:1,anchor:{height:parentHeight,block_hash:receipt.parentHash.slice(2)}};}
export function validateClosedMainnetBurnScan(scan,receipt){const blockHeight=safeJsonUint(receipt.blockHeight,'burn block height');if(scan?.finality_claimed!==false||scan?.inclusion?.height!==blockHeight||String(scan.inclusion.block_hash).toLowerCase()!==receipt.blockHash.slice(2)||scan.inclusion.transition_index!==0||scan.identity?.chain_id!==receipt.domChainId.slice(2)||scan.identity?.network_magic!==receipt.domNetworkMagic)throw new Error('canonical burn scan does not reproduce the exact block receipt');return scan;}
