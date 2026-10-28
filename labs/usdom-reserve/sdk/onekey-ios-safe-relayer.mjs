import {Interface,TypedDataEncoder,getAddress,recoverAddress,Signature,ZeroAddress} from 'ethers';
const abi=['function execTransaction(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,bytes signatures)'];
const iface=new Interface(abi),hex=/^0x[0-9a-f]*$/u,qty=/^(?:0|[1-9][0-9]*)$/u;
const GATES=['relayerRoleSeparationVerified','relayerNoTokenCustodyVerified','signedSafeTxExactCalldataVerified','relayerEconomicCapsVerified','relayerNonceAndNoBlindRetryVerified','emergencyRelayerRotationVerified'];
const exact=(v,k,l)=>{if(v===null||typeof v!=='object'||Array.isArray(v)||JSON.stringify(Object.keys(v).sort())!==JSON.stringify([...k].sort()))throw new Error(`${l} schema invalid`);};
const addr=v=>getAddress(v);
export function validateOneKeyIosSafeRelayer({authority,snapshot,envelope}={}) {
 exact(authority,['schema','status','chainId','relayer','safe','token','governance','guardian','owners','notaries','threshold','allowedTargets','allowedSelectors','maxRelayerBalanceWei','maxOuterGasLimit','maxFeePerGasWei','emergencyReplacementRelayer','gates'],'relayer authority');
 exact(authority.gates,GATES,'relayer gates');
 exact(snapshot,['relayer','ethBalanceWei','tokenBalance','tokenAllowances','pendingNonce'],'relayer snapshot');
 exact(envelope,['schema','attempt','previousTransactionHash','typedData','signatures','outerTransaction'],'relayer envelope');
 if(authority.schema!=='usdom-onekey-ios-relayer-authority-v1'||authority.status!=='ratified'
   ||authority.chainId!=='1'||!Number.isInteger(authority.threshold)||authority.threshold<1||authority.threshold>authority.owners.length
   ||!qty.test(authority.maxRelayerBalanceWei??'')||!qty.test(authority.maxOuterGasLimit??'')||!qty.test(authority.maxFeePerGasWei??''))throw new Error('relayer authority is not ratified');
 const relayer=addr(authority.relayer),safe=addr(authority.safe),token=addr(authority.token),governance=addr(authority.governance),guardian=addr(authority.guardian),replacement=addr(authority.emergencyReplacementRelayer);
 const owners=authority.owners.map(addr),notaries=authority.notaries.map(addr),targets=authority.allowedTargets.map(addr);
 if(new Set(owners).size!==owners.length||new Set(notaries).size!==notaries.length||new Set(targets).size!==targets.length
   ||owners.includes(relayer)||notaries.includes(relayer)||[safe,token,governance,guardian,replacement].includes(relayer)
   ||owners.includes(replacement)||notaries.includes(replacement)||[safe,token,governance,guardian].includes(replacement)
   ||Object.values(authority.gates).some(x=>x!==true))throw new Error('relayer holds a forbidden protocol role or gates are incomplete');
 if(snapshot.relayer!==relayer||!qty.test(snapshot.ethBalanceWei)||BigInt(snapshot.ethBalanceWei)>BigInt(authority.maxRelayerBalanceWei)
   ||snapshot.tokenBalance!=='0'||!Array.isArray(snapshot.tokenAllowances)||snapshot.tokenAllowances.length!==0||!Number.isSafeInteger(snapshot.pendingNonce)||snapshot.pendingNonce<0)throw new Error('relayer custody or balance snapshot rejected');
 const td=envelope.typedData;exact(td,['domain','types','primaryType','message'],'Safe typed data');
 const types={...td.types};delete types.EIP712Domain;
 if(td.primaryType!=='SafeTx'||td.domain?.chainId!==1||addr(td.domain?.verifyingContract)!==safe
   ||TypedDataEncoder.from(types).primaryType!=='SafeTx')throw new Error('Safe typed data domain rejected');
 const m=td.message;exact(m,['to','value','data','operation','safeTxGas','baseGas','gasPrice','gasToken','refundReceiver','nonce'],'SafeTx message');
 if(!targets.includes(addr(m.to))||m.value!=='0'||m.operation!==0||m.gasPrice!=='0'||addr(m.gasToken)!==ZeroAddress||addr(m.refundReceiver)!==ZeroAddress
   ||!hex.test(m.data)||!authority.allowedSelectors.includes(m.data.slice(0,10))||!qty.test(m.safeTxGas)||!qty.test(m.baseGas)||!qty.test(m.nonce))throw new Error('SafeTx exceeds relayer authority');
 const digest=TypedDataEncoder.hash(td.domain,types,m),seen=[];let packed='0x';
 for(const item of envelope.signatures){exact(item,['owner','signature'],'Safe signature');const owner=addr(item.owner);if(recoverAddress(digest,item.signature)!==owner||!owners.includes(owner)||seen.includes(owner))throw new Error('Safe signature rejected');seen.push(owner);packed+=Signature.from(item.signature).serialized.slice(2);}
 if(seen.length<authority.threshold||JSON.stringify(seen)!==JSON.stringify([...seen].sort((a,b)=>a.toLowerCase().localeCompare(b.toLowerCase()))))throw new Error('Safe signature quorum/order rejected');
 const expected=iface.encodeFunctionData('execTransaction',[m.to,m.value,m.data,m.operation,m.safeTxGas,m.baseGas,m.gasPrice,m.gasToken,m.refundReceiver,packed]);
 const outer=envelope.outerTransaction;exact(outer,['from','to','value','data','nonce','gasLimit','maxFeePerGas','maxPriorityFeePerGas','chainId'],'outer transaction');
 if(envelope.schema!=='usdom-onekey-ios-safe-relayer-envelope-v1'||envelope.attempt!==1||envelope.previousTransactionHash!==null
   ||addr(outer.from)!==relayer||addr(outer.to)!==safe||outer.value!=='0'||outer.data!==expected||outer.nonce!==snapshot.pendingNonce||outer.chainId!==1
   ||!qty.test(outer.gasLimit)||BigInt(outer.gasLimit)>BigInt(authority.maxOuterGasLimit)||!qty.test(outer.maxFeePerGas)||BigInt(outer.maxFeePerGas)>BigInt(authority.maxFeePerGasWei)
   ||!qty.test(outer.maxPriorityFeePerGas)||BigInt(outer.maxPriorityFeePerGas)>BigInt(outer.maxFeePerGas))throw new Error('outer relayer transaction is mutable, uncapped or retrying');
 return Object.freeze({safeTxDigest:digest,relayer,safe,nonce:outer.nonce,gasOnly:true,hardwareSigningApproved:false});
}
export const SAFE_TX_TYPES=Object.freeze({SafeTx:Object.freeze([{name:'to',type:'address'},{name:'value',type:'uint256'},{name:'data',type:'bytes'},{name:'operation',type:'uint8'},{name:'safeTxGas',type:'uint256'},{name:'baseGas',type:'uint256'},{name:'gasPrice',type:'uint256'},{name:'gasToken',type:'address'},{name:'refundReceiver',type:'address'},{name:'nonce',type:'uint256'}])});
