import assert from 'node:assert/strict';
import test from 'node:test';
import {
  pilotFailureLine,pilotFailureRecord,releaseFailureLine,writePilotFailure,
} from '../../sdk/pilot-safe-diagnostics.mjs';

const secrets=[
  'rawtx:0x02f8_SENTINEL','witness:SENTINEL','rho:SENTINEL','nullifier-secret:SENTINEL',
  'memo plaintext SENTINEL','depositId:SENTINEL','funder:SENTINEL',
  'receivingCommitment:SENTINEL','burnId:SENTINEL','requestId:SENTINEL','recipient:SENTINEL',
];

test('pilot failure records never inspect exception message, stack or cause',()=>{
  const error=new Error(secrets.join('|'));
  error.stack=secrets.toReversed().join('\n');
  error.cause={rawTransaction:secrets.join('')};
  const line=pilotFailureLine('closed-mainnet-deposit-prepare',error);
  assert.deepEqual(JSON.parse(line),{
    schema:'usdom-pilot-safe-diagnostic/v1',ok:false,
    operation:'closed-mainnet-deposit-prepare',code:'PILOT_OPERATION_REJECTED',
  });
  for(const secret of secrets) assert.equal(line.includes(secret),false);
});

test('stderr writer emits one bounded structured line without phase identifiers',()=>{
  let output='';
  writePilotFailure('finalized-burn-submission-prepare',new Error(secrets.join()),{
    stream:{write(value){output+=value;}},
  });
  assert.equal(output.split('\n').length,2);
  assert.equal(output.length<256,true);
  for(const secret of secrets) assert.equal(output.includes(secret),false);
});

test('diagnostic operation is closed rather than attacker supplied',()=>{
  assert.throws(()=>pilotFailureRecord('depositId=SENTINEL',new Error('burnId=SENTINEL')),
    /unsupported pilot diagnostic operation/);
});

test('release diagnostic drops child stderr, argv, env and private JSON sentinels',()=>{
  const error=new Error(secrets.join('|'));
  error.stderr=Buffer.from(secrets.join(':'));
  error.stdout=Buffer.from(secrets.toReversed().join(':'));
  error.argv=secrets;
  error.env={RPC_URL:secrets.join('')};
  error.privateJson={witness:secrets.join('')};
  const line=releaseFailureLine('checkpoint-release-observation',error);
  assert.deepEqual(JSON.parse(line),{
    schema:'usdom-release-safe-diagnostic/v1',ok:false,
    operation:'checkpoint-release-observation',code:'RELEASE_OPERATION_REJECTED',
  });
  for(const secret of secrets) assert.equal(line.includes(secret),false);
});
