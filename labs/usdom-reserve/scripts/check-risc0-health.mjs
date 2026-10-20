import {Contract,JsonRpcProvider,keccak256} from 'ethers';
import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {assessRiscZeroMainnetHealth} from '../sdk/risc0-health.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const rpcUrl=process.env.ETHEREUM_RPC_URL;
const directAbi=['function SELECTOR() view returns (bytes4)','function VERSION() view returns (string)'];
const stopAbi=['function paused() view returns (bool)','function verifier() view returns (address)'];
const codeHash=async(provider,address,blockTag)=>keccak256(await provider.send('eth_getCode',[address,blockTag]));

async function observe(reference) {
  const provider=new JsonRpcProvider(rpcUrl);
  try {
    const [chainId,finalized]=await Promise.all([
      provider.send('eth_chainId',[]).then(BigInt),provider.send('eth_getBlockByNumber',['finalized',false]),
    ]);
    if(!finalized?.hash || !/^0x[0-9a-fA-F]+$/.test(finalized.number??'')) {
      throw new Error('RPC did not return a canonical finalized block');
    }
    const finalizedTag=finalized.number;
    const callOptions={blockTag:finalizedTag};
    const direct=new Contract(reference.verifier_address,directAbi,provider);
    const stop=new Contract(reference.emergency_stop_wrapper_address,stopAbi,provider);
    const [directCodeHash,selector,version,stopCodeHash,paused,verifier]=await Promise.all([
      codeHash(provider,reference.verifier_address,finalizedTag),direct.SELECTOR(callOptions),
      direct.VERSION(callOptions),codeHash(provider,reference.emergency_stop_wrapper_address,finalizedTag),
      stop.paused(callOptions),stop.verifier(callOptions),
    ]);
    const snapshotAfter=await provider.send('eth_getBlockByNumber',[finalizedTag,false]);
    return {chainId:chainId.toString(),finalizedBlockNumber:BigInt(finalized.number).toString(),
      finalizedBlockHash:finalized.hash,snapshotBlockHashAfter:snapshotAfter?.hash??null,
      riscZeroVerifier:{address:reference.verifier_address,codeHash:directCodeHash,selector,version},
      riscZeroEmergencyStop:{address:reference.emergency_stop_wrapper_address,codeHash:stopCodeHash,
        paused,verifier}};
  } finally { await provider.destroy(); }
}

if(process.argv.length!==2 || !rpcUrl) {
  console.error('Usage: ETHEREUM_RPC_URL=<url> node scripts/check-risc0-health.mjs');
  process.exitCode=2;
} else {
  try {
    const reference=parseStrictJson(
      await readFile(path.join(root,'config/risc0-ethereum-mainnet-v3.json'),'utf8'),
      {label:'config/risc0-ethereum-mainnet-v3.json'},
    );
    const observation=await observe(reference);
    const report=assessRiscZeroMainnetHealth({reference,observation});
    console.log(JSON.stringify({...report,observation},null,2));
    if(!report.healthy) process.exitCode=1;
  } catch(error) {
    const message=String(error?.message??error).split(rpcUrl).join('[redacted RPC URL]');
    console.error(JSON.stringify({healthy:false,error:message},null,2));
    process.exitCode=2;
  }
}
