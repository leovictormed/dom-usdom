import {createHash} from 'node:crypto';
import {getAddress,keccak256,Transaction} from 'ethers';
import {canonicalUnsignedDecimal} from './ethereum-quantity.mjs';

const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)
 &&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const decimal=(value,max)=>canonicalUnsignedDecimal(value,{maximum:max});

export function validateSafeDeploymentRelayerPolicy({policy,policyBytes,keystore,keystoreBytes,pkg}) {
 if(!exact(policy,['schema','chainId','relayer','maxGasLimit','maxFeePerGas','maxPriorityFeePerGas',
  'maxTotalGasCost','encryptedKeystoreSha256','gasOnlyAcknowledged'])
  ||policy.schema!=='usdom-safe-deployment-relayer-policy/v1'||policy.chainId!=='1'
  ||getAddress(policy.relayer)!==policy.relayer||policy.gasOnlyAcknowledged!==true
  ||policy.encryptedKeystoreSha256!==sha256(keystoreBytes)
  ||decimal(policy.maxGasLimit,1_000_000n)!==policy.maxGasLimit
  ||decimal(policy.maxFeePerGas,100_000_000_000n)!==policy.maxFeePerGas
  ||decimal(policy.maxPriorityFeePerGas,10_000_000_000n)!==policy.maxPriorityFeePerGas
  ||decimal(policy.maxTotalGasCost,300_000_000_000_000_000n)!==policy.maxTotalGasCost)throw new Error('Safe deployment relayer policy rejected');
 if(!exact(keystore,['version','id','address','crypto'])||keystore.version!==3
  ||keystore.address!==policy.relayer.slice(2).toLowerCase()||typeof keystore.id!=='string'
  ||!exact(keystore.crypto,['ciphertext','cipherparams','cipher','kdf','kdfparams','mac'])
  ||keystore.crypto.cipher!=='aes-128-ctr'||!/^[0-9a-f]+$/u.test(keystore.crypto.ciphertext)
  ||!/^[0-9a-f]{64}$/u.test(keystore.crypto.mac)||!['scrypt','pbkdf2'].includes(keystore.crypto.kdf)
  ||!exact(keystore.crypto.cipherparams,['iv'])||!/^[0-9a-f]{32}$/u.test(keystore.crypto.cipherparams.iv)
  ||typeof keystore.crypto.kdfparams!=='object')throw new Error('encrypted gas relayer keystore rejected');
 const forbidden=new Set([pkg.factory,pkg.singleton,pkg.fallbackHandler,
  ...(pkg.controls??[]).flatMap(control=>[control.safe,...control.owners])].map(value=>getAddress(value)));
 if(forbidden.has(policy.relayer))throw new Error('gas relayer overlaps Safe authority or custody');
 return {policyHash:keccak256(policyBytes),keystoreHash:sha256(keystoreBytes)};
}

export function buildSafeDeploymentRelayerEnvelope({role,input,pkg,packageBytes,policy,policyBytes,keystore,
 keystoreBytes,nonce,gasLimit,maxFeePerGas,maxPriorityFeePerGas}) {
 const control=pkg.controls?.find(value=>value.role===role);
 const hashes=validateSafeDeploymentRelayerPolicy({policy,policyBytes,keystore,keystoreBytes,pkg});
 const canonicalNonce=decimal(nonce,BigInt(Number.MAX_SAFE_INTEGER)),gas=decimal(gasLimit,BigInt(policy.maxGasLimit));
 const fee=decimal(maxFeePerGas,BigInt(policy.maxFeePerGas)),priority=decimal(maxPriorityFeePerGas,BigInt(policy.maxPriorityFeePerGas));
 const cost=(BigInt(gas)*BigInt(fee)).toString();
 if(!control||getAddress(input.to)!==getAddress(control.to)||input.value!=='0'||keccak256(input.data)!==control.dataHash
  ||priority==='0'||BigInt(priority)>BigInt(fee)||BigInt(cost)>BigInt(policy.maxTotalGasCost))throw new Error('Safe relayer envelope inputs rejected');
 return {schema:'usdom-safe-deployment-relayer-envelope/v1',role,chainId:'1',relayer:policy.relayer,
  to:getAddress(control.to),value:'0',dataHash:control.dataHash,nonce:canonicalNonce,gasLimit:gas,
  maxFeePerGas:fee,maxPriorityFeePerGas:priority,maximumGasCost:cost,packageHash:keccak256(packageBytes),
  policyHash:hashes.policyHash,encryptedKeystoreSha256:hashes.keystoreHash};
}

export function validateSafeDeploymentRelayerRaw({role,rawBytes,envelope,input,pkg,packageBytes,policy,policyBytes,
 keystore,keystoreBytes}) {
 const raw=rawBytes.toString('utf8').trim();if(`${raw}\n`!==rawBytes.toString('utf8')||!/^0x[0-9a-f]+$/u.test(raw))throw new Error('Safe relayer raw framing rejected');
 const expected=buildSafeDeploymentRelayerEnvelope({role,input,pkg,packageBytes,policy,policyBytes,keystore,keystoreBytes,
  nonce:envelope.nonce,gasLimit:envelope.gasLimit,maxFeePerGas:envelope.maxFeePerGas,
  maxPriorityFeePerGas:envelope.maxPriorityFeePerGas});
 if(!exact(envelope,Object.keys(expected))||JSON.stringify(envelope)!==JSON.stringify(expected))throw new Error('Safe relayer envelope drift');
 const control=pkg.controls.find(value=>value.role===role),tx=Transaction.from(raw);
 if(tx.serialized!==raw||tx.signature===null||tx.hash===null||tx.chainId!==1n||tx.type!==2
  ||tx.from!==policy.relayer||tx.to!==getAddress(control.to)||tx.value!==0n||tx.data.toLowerCase()!==control.data.toLowerCase()
  ||tx.nonce!==Number(envelope.nonce)||tx.gasLimit!==BigInt(envelope.gasLimit)
  ||tx.maxFeePerGas!==BigInt(envelope.maxFeePerGas)||tx.maxPriorityFeePerGas!==BigInt(envelope.maxPriorityFeePerGas)
  ||tx.accessList.length!==0)throw new Error('Safe deployment raw differs from relayer envelope');
 return {schema:'usdom-safe-deployment-raw/v1',role,safe:getAddress(control.safe),from:tx.from,nonce:envelope.nonce,
  to:tx.to,dataHash:keccak256(tx.data),transactionHash:tx.hash,gasLimit:tx.gasLimit.toString(),
  maxFeePerGas:tx.maxFeePerGas.toString(),rawHash:keccak256(raw)};
}
