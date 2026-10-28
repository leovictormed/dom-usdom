import {createHash} from 'node:crypto';
import {getAddress,Transaction,TypedDataEncoder,verifyTypedData} from 'ethers';
import {parseStrictJsonBytes} from './strict-json.mjs';
import {readDirectFile} from './direct-project-file.mjs';
import {writePrivateFileDurableNew} from './durable-private-file.mjs';
import {validateOneKeyBlePhysicalCeremonyAuthority} from './onekey-ble-physical-ceremony-evidence.mjs';

const sha=/^[0-9a-f]{64}$/u;
const COMMON=['schema','source','deviceId','firmware','address','appArtifactSha256','packageArtifactSha256','chainId','broadcast','fundsAtRisk','physicalTestTranscriptSha256','payload','result'];
const SOURCE=['kind','mock','emulator'];
const TXPAY=['purpose','type','nonce','maxPriorityFeePerGas','maxFeePerGas','gasLimit','to','value','data'];
const TXRES=['signedRawTransaction','signerAddress','rawTransactionSha256'];
const TDPAY=['purpose','domain','types','primaryType','message','digest'];
const TDRES=['signature','signerAddress'];
const exact=(v,k,l)=>{if(v===null||typeof v!=='object'||Array.isArray(v)||JSON.stringify(Object.keys(v).sort())!==JSON.stringify([...k].sort()))throw new Error(`${l} schema is invalid`);};
const canonHex=/^0x(?:0|[1-9a-f][0-9a-f]*)$/u;
const bytesHash=b=>createHash('sha256').update(b).digest('hex');
function common(authority,value,schema,allowMock) {
 validateOneKeyBlePhysicalCeremonyAuthority(authority,{requireRatified:true}); exact(value,COMMON,'physical signing exercise');exact(value.source,SOURCE,'exercise source');
 if(value.schema!==schema||value.source.kind!=='pinned-electron-app'||value.source.emulator!==false
   ||value.source.mock!==(allowMock?true:false)||value.deviceId!==authority.expectedDeviceId
   ||value.firmware===undefined||!authority.firmwareAllowlist.includes(value.firmware)
   ||value.address!==authority.expectedAddress||value.appArtifactSha256!==authority.appArtifactSha256
   ||value.packageArtifactSha256!==authority.packageArtifactSha256||value.chainId!=='1'
   ||value.broadcast!==false||value.fundsAtRisk!==false||!sha.test(value.physicalTestTranscriptSha256??'')) throw new Error('physical signing exercise is unbound or synthetic');
}
function checkTx(authority,value,allowMock) {
 common(authority,value,'usdom-onekey-ble-eip1559-physical-exercise-v1',allowMock);exact(value.payload,TXPAY,'EIP-1559 payload');exact(value.result,TXRES,'EIP-1559 result');
 const p=value.payload;
 if(p.purpose!=='onekey-physical-signing-test'||p.type!=='0x2'||p.to!==authority.expectedAddress||p.value!=='0x0'||p.data!=='0x'
   ||![p.nonce,p.maxPriorityFeePerGas,p.maxFeePerGas,p.gasLimit].every(x=>canonHex.test(x))) throw new Error('EIP-1559 test payload could spend funds or is noncanonical');
 let tx;try{tx=Transaction.from(value.result.signedRawTransaction);}catch{throw new Error('EIP-1559 raw transaction is invalid');}
 const nonce=BigInt(p.nonce);
 if(nonce>BigInt(Number.MAX_SAFE_INTEGER)||tx.type!==2||tx.chainId!==1n||getAddress(tx.from)!==authority.expectedAddress||tx.to!==p.to||tx.value!==0n||tx.data!=='0x'
   ||tx.nonce!==Number(nonce)||tx.maxPriorityFeePerGas!==BigInt(p.maxPriorityFeePerGas)||tx.maxFeePerGas!==BigInt(p.maxFeePerGas)||tx.gasLimit!==BigInt(p.gasLimit)
   ||value.result.signerAddress!==authority.expectedAddress||value.result.rawTransactionSha256!==bytesHash(Buffer.from(value.result.signedRawTransaction.slice(2),'hex'))) throw new Error('EIP-1559 signer/raw/payload verification failed');
 return value;
}
function checkTyped(authority,value,allowMock) {
 common(authority,value,'usdom-onekey-ble-eip712-physical-exercise-v1',allowMock);exact(value.payload,TDPAY,'EIP-712 payload');exact(value.result,TDRES,'EIP-712 result');
 const p=value.payload;
 if(p.purpose!=='onekey-physical-signing-test'||p.domain?.chainId!==1||p.primaryType!=='OneKeyPhysicalSigningTest'
   ||TypedDataEncoder.hash(p.domain,p.types,p.message)!==p.digest
   ||getAddress(verifyTypedData(p.domain,p.types,p.message,value.result.signature))!==authority.expectedAddress
   ||value.result.signerAddress!==authority.expectedAddress) throw new Error('EIP-712 signer/digest verification failed');
 return value;
}
export const validatePhysicalEip1559Exercise=(a,v)=>checkTx(a,v,false);
export const validatePhysicalEip712Exercise=(a,v)=>checkTyped(a,v,false);
export const verifySyntheticEip1559ExerciseForTest=(a,v)=>checkTx(a,v,true);
export const verifySyntheticEip712ExerciseForTest=(a,v)=>checkTyped(a,v,true);

export function ratifyPhysicalSigningExercises({authority,eip1559Bytes,eip712Bytes,ratification}) {
 const tx=parseStrictJsonBytes(eip1559Bytes,{label:'EIP-1559 physical exercise'}),td=parseStrictJsonBytes(eip712Bytes,{label:'EIP-712 physical exercise'});
 validatePhysicalEip1559Exercise(authority,tx);validatePhysicalEip712Exercise(authority,td);
 exact(ratification,['schema','decision','singleOperator','residualRiskAccepted','eip1559BytesSha256','eip712BytesSha256'],'physical signing ratification');
 if(ratification.schema!=='usdom-onekey-ble-physical-signing-ratification-v1'||ratification.decision!=='approve-observed-eip1559-and-eip712-gate'
   ||ratification.singleOperator!==true||ratification.residualRiskAccepted!==true||ratification.eip1559BytesSha256!==bytesHash(eip1559Bytes)||ratification.eip712BytesSha256!==bytesHash(eip712Bytes)) throw new Error('physical signing ratification is invalid or unbound');
 return {schema:'usdom-onekey-ble-physical-signing-readiness-v1',status:'single-operator-ratified',singleOperator:true,
  residualRisk:'one operator performed and ratified both physical signing exercises',hardwareSigningApproved:false,
  eip1559BytesSha256:ratification.eip1559BytesSha256,eip712BytesSha256:ratification.eip712BytesSha256,
  readinessGates:{production_onekey_eip1559_and_eip712_signing_verified:true}};
}

export function validatePhysicalSigningReadiness(value) {
 exact(value,['schema','status','singleOperator','residualRisk','hardwareSigningApproved','eip1559BytesSha256','eip712BytesSha256','readinessGates'],'physical signing readiness');
 exact(value.readinessGates,['production_onekey_eip1559_and_eip712_signing_verified'],'physical signing gates');
 if(value.schema!=='usdom-onekey-ble-physical-signing-readiness-v1'||value.status!=='single-operator-ratified'||value.singleOperator!==true
   ||value.hardwareSigningApproved!==false||!sha.test(value.eip1559BytesSha256??'')||!sha.test(value.eip712BytesSha256??'')
   ||value.readinessGates.production_onekey_eip1559_and_eip712_signing_verified!==true) throw new Error('physical signing readiness overstates authority');
 return value;
}

export async function materializePhysicalSigningRatification({authorityPath,eip1559Path,eip712Path,ratificationPath,outputPath}) {
 const [a,x,y,r]=await Promise.all([readDirectFile(authorityPath,{minimum:2,maximum:32768,exactMode:0o600,label:'physical authority'}),readDirectFile(eip1559Path,{minimum:2,maximum:131072,exactMode:0o600,label:'EIP-1559 physical exercise'}),readDirectFile(eip712Path,{minimum:2,maximum:131072,exactMode:0o600,label:'EIP-712 physical exercise'}),readDirectFile(ratificationPath,{minimum:2,maximum:32768,exactMode:0o600,label:'physical signing ratification'})]);
 const result=ratifyPhysicalSigningExercises({authority:parseStrictJsonBytes(a,{label:'physical authority'}),eip1559Bytes:x,eip712Bytes:y,ratification:parseStrictJsonBytes(r,{label:'physical signing ratification'})});
 await writePrivateFileDurableNew(outputPath,`${JSON.stringify(result,null,2)}\n`,{maximum:32768});return result;
}
