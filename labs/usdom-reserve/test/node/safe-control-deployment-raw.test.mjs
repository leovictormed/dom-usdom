import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,chmod,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {Wallet,keccak256} from 'ethers';

const script=new URL('../../scripts/check-safe-control-deployment-raw-transaction.mjs',import.meta.url);
const wallet=new Wallet('0x0123456789012345678901234567890123456789012345678901234567890123');
const control={role:'governance',safe:'0x0000000000000000000000000000000000000100',
  to:'0x0000000000000000000000000000000000000200',data:'0x12345678'};

test('Safe deployment raw journal binds signer, nonce, chain, target and calldata',async()=>{
  const dir=await mkdtemp(path.join(tmpdir(),'safe-raw-'));
  try {
    const packagePath=path.join(dir,'package.json'),rawPath=path.join(dir,'raw.txt');
    await writeFile(packagePath,JSON.stringify({controls:[control]})+'\n',{mode:0o600});
    const tx={type:2,chainId:1,nonce:7,to:control.to,value:0,data:control.data,
      gasLimit:200000,maxFeePerGas:10_000_000_000n,maxPriorityFeePerGas:2_000_000_000n,accessList:[]};
    const raw=await wallet.signTransaction(tx); await writeFile(rawPath,raw+'\n',{mode:0o600});
    await chmod(packagePath,0o600); await chmod(rawPath,0o600);
    const run=(nonce='7')=>spawnSync(process.execPath,[script.pathname,'governance',nonce],{
      encoding:'utf8',env:{...process.env,USDOM_SAFE_PACKAGE:packagePath,
        USDOM_SAFE_DEPLOYMENT_RAW:rawPath,USDOM_SAFE_PRIMARY_OWNER:wallet.address}});
    const valid=run(); assert.equal(valid.status,0,valid.stderr);
    const observed=JSON.parse(valid.stdout); assert.equal(observed.transactionHash,keccak256(raw));
    assert.notEqual(run('8').status,0);
    const changed=await wallet.signTransaction({...tx,data:'0xabcdef01'});
    await writeFile(rawPath,changed+'\n',{mode:0o600}); assert.notEqual(run().status,0);
  } finally { await rm(dir,{recursive:true,force:true}); }
});
