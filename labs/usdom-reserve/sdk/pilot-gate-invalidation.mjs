const hash=/^0x[0-9a-f]{64}$/;
const decimal=/^(0|[1-9][0-9]*)$/;
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());

function quantity(value,label){
 if(typeof value!=='string'||!decimal.test(value)) throw new Error(`${label} is not canonical decimal`);
 return BigInt(value);
}
function digest(value,label){if(typeof value!=='string'||!hash.test(value)||/^0x0{64}$/.test(value)) throw new Error(`${label} is invalid`);return value;}
function common(value,schema,keys,label){
 if(!exact(value,keys)||value.schema!==schema) throw new Error(`${label} schema is invalid`);
 digest(value.transactionHash,`${label} transactionHash`); digest(value.blockHash,`${label} blockHash`);
 digest(value.finalizedBlockHash,`${label} finalizedBlockHash`); digest(value.snapshotCommitment,`${label} snapshotCommitment`);
 const block=quantity(value.blockNumber,`${label} blockNumber`),index=quantity(value.transactionIndex,`${label} transactionIndex`),finalized=quantity(value.finalizedBlockNumber,`${label} finalizedBlockNumber`),generation=quantity(value.generation,`${label} generation`);
 if(finalized<block) throw new Error(`${label} finalized head precedes transaction`);
 if(finalized===block&&value.finalizedBlockHash!==value.blockHash) throw new Error(`${label} finalized hash differs at transaction height`);
 return {block,index,finalized,generation};
}

export function validatePilotGateFinality(value){
 const keys=['schema','transactionHash','safeTxHash','blockNumber','blockHash','transactionIndex','finalizedBlockNumber','finalizedBlockHash','snapshotCommitment','expectedAuthorization','generation'];
 const position=common(value,'usdom-pilot-deposit-gate-finalized/v2',keys,'pilot gate finality');
 digest(value.safeTxHash,'pilot gate safeTxHash'); digest(value.expectedAuthorization,'pilot gate expectedAuthorization');
 return position;
}

export function validatePilotGateInvalidation(value,kind){
 if(kind!=='clear'&&kind!=='cancel') throw new Error('pilot gate invalidation kind is invalid');
 const keys=['schema','transactionHash','blockNumber','blockHash','transactionIndex','finalizedBlockNumber','finalizedBlockHash','snapshotCommitment','generation'];
 return common(value,`usdom-pilot-deposit-gate-${kind}-finalized/v2`,keys,`pilot gate ${kind} finality`);
}

export function validatePilotGateInvalidationSequence(gate,terminal,kind){
 const first=validatePilotGateFinality(gate),last=validatePilotGateInvalidation(terminal,kind);
 if(gate.snapshotCommitment!==terminal.snapshotCommitment||first.generation!==last.generation) throw new Error('pilot gate invalidation generation differs from gate');
 if(last.block<first.block||(last.block===first.block&&last.index<=first.index)) throw new Error('pilot gate invalidation does not follow gate canonically');
 if(last.block===first.block&&terminal.blockHash!==gate.blockHash) throw new Error('pilot gate invalidation block hash differs at shared height');
 if(last.finalized<first.finalized) throw new Error('pilot gate invalidation finalized head regressed');
 if(last.finalized===first.finalized&&terminal.finalizedBlockHash!==gate.finalizedBlockHash) throw new Error('pilot gate invalidation finalized hash differs at shared height');
 return {kind,gate:first,invalidation:last};
}
