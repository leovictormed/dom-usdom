import {createHash} from 'node:crypto';
import {validateFinalizedDepositIssuance} from './finalized-deposit-issuance.mjs';
import {validatePersistedIssuanceBlock,validateQueuedIssuanceReceipt} from './closed-mainnet-block.mjs';
import {validateFinalizedDepositSource} from './finalized-deposit-source.mjs';
import {parseStrictJsonBytes} from './strict-json.mjs';

const H=/^[0-9a-f]{64}$/;
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)
  &&JSON.stringify(Object.keys(v).sort())===JSON.stringify([...keys].sort());
const sha=b=>createHash('sha256').update(b).digest('hex');

export function validateNativeFinalizedDepositVector({manifestBytes,manifestPin,sourceBytes,
  releaseConfigBytes,witness,index,registration,submission,block,observation}) {
  if(!H.test(manifestPin)||sha(manifestBytes)!==manifestPin) throw new Error('native manifest pin mismatch');
  if(!Buffer.isBuffer(sourceBytes)||sourceBytes.length<2||sourceBytes.length>4*1024*1024
      ||!Buffer.isBuffer(releaseConfigBytes)||releaseConfigBytes.length<2
      ||releaseConfigBytes.length>4*1024*1024
      ||sha(sourceBytes)!==index?.source_sha256
      ||sha(releaseConfigBytes)!==index?.release_config_sha256) {
    throw new Error('finalized deposit source or release bytes differ from the witness index');
  }
  // The terminal vector is an independent release gate.  Do not accept the
  // witness builder's self-reported index without reopening the authenticated
  // source preimage and reconciling every public deposit/finality identity it
  // exposes.  Otherwise a valid wallet/block tuple could be paired with an
  // unrelated source file and a correspondingly rewritten index.
  const source=validateFinalizedDepositSource(parseStrictJsonBytes(sourceBytes,{
    label:'finalized-deposit-source.json',maxBytes:4*1024*1024,maxDepth:64,
  }));
  const releaseConfig=parseStrictJsonBytes(releaseConfigBytes,{
    label:'proof-reserve release configuration',maxBytes:4*1024*1024,maxDepth:32,
  });
  const finalized=source.finality.finalized_header;
  if(!releaseConfig||typeof releaseConfig!=='object'||Array.isArray(releaseConfig)
      ||releaseConfig.ethereumChainId!=='1'
      ||typeof releaseConfig.reserve!=='string'
      ||releaseConfig.reserve.toLowerCase()!==source.reserve.toLowerCase()
      ||source.releaseConfigSha256!==index.release_config_sha256
      ||source.nativeManifestSha256!==manifestPin
      ||source.transactionHash!==index.source_transaction_hash
      ||source.depositId!==index.deposit_id
      ||source.funder.toLowerCase()!==index.funder
      ||source.amountBaseUnits!==index.amount_base_units
      ||source.receivingCommitment!==index.receiving_commitment
      ||source.transactionIndex!==index.transaction_index
      ||source.receiptLogIndex!==index.receipt_log_index
      ||source.depositBlockNumber!==index.deposit_block_number
      ||source.depositBlockHash!==index.deposit_block_hash
      ||finalized.beacon.slot!==index.finalized_beacon_slot
      ||finalized.execution.block_number!==index.finalized_execution_block_number
      ||finalized.execution.block_hash!==index.finalized_execution_block_hash) {
    throw new Error('witness index does not match the authenticated finalized-deposit source');
  }
  const binding=validateFinalizedDepositIssuance({index,registration,witness,manifestSha256:manifestPin});
  if(!exact(observation,['schema','native_manifest_sha256','deposit_id','note_commitment',
    'amount_base_units','available_balance_base_units','canonical','dom_chain_id','block_height',
    'block_hash','snapshot_generation','snapshot_seal','history_authenticated','broadcasts','mines'])
    ||observation.schema!=='usdom-canonical-deposit-observation-v1'
    ||observation.native_manifest_sha256!==manifestPin
    ||observation.deposit_id!==binding.depositId.slice(2)
    ||observation.note_commitment!==binding.noteCommitment.slice(2)
    ||observation.amount_base_units!=='1000000'||observation.available_balance_base_units!=='1000000'
    ||observation.canonical!==true||observation.history_authenticated!==true
    ||observation.broadcasts!==false||observation.mines!==false
    ||observation.block_height!=='1'||observation.block_hash!==block.blockHash.slice(2)
    ||observation.dom_chain_id!==block.domChainId.slice(2)
    ||!/^[1-9][0-9]*$/.test(observation.snapshot_generation)
    ||!/^[0-9a-f]{96}$/.test(observation.snapshot_seal)) {
    throw new Error('canonical wallet observation does not bind the finalized deposit');
  }
  validateQueuedIssuanceReceipt(submission,{tip_height:Number(block.parentHeight),
    tip_hash:block.parentHash.slice(2),chain_id:block.domChainId.slice(2),genesis_hash:block.domGenesisHash.slice(2)});
  const identity={tip_height:1,tip_hash:block.blockHash.slice(2),chain_id:block.domChainId.slice(2),
    genesis_hash:block.domGenesisHash.slice(2)};
  validatePersistedIssuanceBlock(block,submission,identity);
  if(submission.depositId!==binding.depositId||submission.noteCommitment!==binding.noteCommitment
      ||submission.witnessSha256!==binding.witnessSha256||submission.amountBaseUnits!=='1000000') {
    throw new Error('issuance submission does not bind the finalized-deposit witness');
  }
  return Object.freeze({schema:'usdom-native-finalized-deposit-vector-validation-v1',
    manifestSha256:manifestPin,witnessSha256:binding.witnessSha256,depositId:binding.depositId,
    noteCommitment:binding.noteCommitment,blockHash:block.blockHash,blockHeight:'1',
    amountBaseUnits:'1000000',historyAuthenticated:true,exactlyOneBlock:true,
    broadcastsEthereum:false,continuousMining:false});
}
