import {getAddress} from 'ethers';
import {SAFE_CONTROL_SPECS} from './safe-control-deployment.mjs';
import {observeRecoverableSafeControlRoleBeforeRecovery} from './safe-control-observation.mjs';

function fail(message) { throw new Error(message); }
function blockIdentity(block) {
  if(!block||!Number.isSafeInteger(block.number)||block.number<0
      ||typeof block.hash!=='string'||!/^0x[0-9a-f]{64}$/.test(block.hash)) {
    fail('Safe deployment finalized block is invalid');
  }
  return {number:block.number,hash:block.hash};
}

async function classifyOne({packageDocument,role,rpcUrl,providerFactory}) {
  const control=packageDocument?.controls?.find(value=>value.role===role);
  if(!control||!SAFE_CONTROL_SPECS.some(value=>value.role===role)) fail('Safe deployment role is invalid');
  const provider=providerFactory(rpcUrl);
  try {
    const network=await provider.getNetwork();
    if(network.chainId!==1n) fail('Safe deployment target is not on Ethereum mainnet');
    const initial=blockIdentity(await provider.getBlock('finalized'));
    provider.pinFinalizedSnapshot?.(initial.number,initial.hash);
    const address=getAddress(control.safe);
    const [code,nonce]=await Promise.all([
      provider.getCode(address,initial.number),provider.getTransactionCount(address,initial.number),
    ]);
    const [canonical,codeAgain,nonceAgain]=await Promise.all([
      provider.getBlock(initial.number),provider.getCode(address,initial.number),
      provider.getTransactionCount(address,initial.number),
    ]);
    if(blockIdentity(canonical).hash!==initial.hash||codeAgain!==code||nonceAgain!==nonce) {
      fail('Safe deployment target changed during observation');
    }
    if(code==='0x') {
      if(nonce!==0) fail('Safe CREATE2 destination has a nonzero nonce without code');
      return {state:'vacant',role,address};
    }
  } finally { if(typeof provider?.destroy==='function') await provider.destroy(); }
  const observed=await observeRecoverableSafeControlRoleBeforeRecovery({
    packageDocument,role,rpcUrl,providerFactory,
  });
  return {state:'deployed',role,address:getAddress(control.safe),configurationHash:observed.configurationHash,
    runtimeCodeHash:observed.runtimeCodeHash};
}

/** Classify a predicted CREATE2 target as vacant or as the exact expected,
 * untouched Safe. Mixed or incompatible independently observed states fail. */
export async function classifyRecoverableSafeDeploymentTargetConsensus({
  packageDocument,role,rpcUrls,providerFactory,
}={}) {
  if(!Array.isArray(rpcUrls)||rpcUrls.length<2||rpcUrls.length>5
      ||new Set(rpcUrls).size!==rpcUrls.length||typeof providerFactory!=='function') {
    fail('two to five independent Safe deployment RPC sources are required');
  }
  const results=[];
  for(const rpcUrl of rpcUrls) results.push(await classifyOne({
    packageDocument,role,rpcUrl,providerFactory,
  }));
  if(results.some(value=>JSON.stringify(value)!==JSON.stringify(results[0]))) {
    fail('Safe deployment target state disagrees across RPC sources');
  }
  return results[0];
}
