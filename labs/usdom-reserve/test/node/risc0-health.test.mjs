import test from 'node:test';
import assert from 'node:assert/strict';
import {assessRiscZeroMainnetHealth} from '../../sdk/risc0-health.mjs';
import {PINNED_RISC0_MAINNET_V3} from '../../sdk/risc0-verifier-reference.mjs';

const hash=byte=>'0x'+byte.repeat(32);
const address=n=>'0x'+n.toString(16).padStart(40,'0');

function observation() {
  return {chainId:'1',
    genesisBlockHash:'0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3',
    finalizedBlockNumber:'24000000',finalizedBlockHash:hash('11'),
    snapshotBlockHashAfter:hash('11'),
    riscZeroVerifier:{address:PINNED_RISC0_MAINNET_V3.verifier_address,
      codeHash:PINNED_RISC0_MAINNET_V3.observed_runtime_code_hash,
      selector:PINNED_RISC0_MAINNET_V3.verifier_selector,version:PINNED_RISC0_MAINNET_V3.verifier_version},
    riscZeroEmergencyStop:{address:PINNED_RISC0_MAINNET_V3.emergency_stop_wrapper_address,
      codeHash:PINNED_RISC0_MAINNET_V3.emergency_stop_wrapper_runtime_code_hash,
      paused:false,verifier:PINNED_RISC0_MAINNET_V3.verifier_address}};
}

test('RISC Zero upstream health accepts the reviewed live direct verifier and clear stop signal',()=>{
  const report=assessRiscZeroMainnetHealth({reference:{...PINNED_RISC0_MAINNET_V3},
    observation:observation()});
  assert.equal(report.healthy,true,JSON.stringify(report.blockers));
  const embedded={...observation(),token:{}};
  assert.equal(assessRiscZeroMainnetHealth({reference:{...PINNED_RISC0_MAINNET_V3},
    observation:embedded,standalone:false}).healthy,true);
  assert.equal(assessRiscZeroMainnetHealth({reference:{...PINNED_RISC0_MAINNET_V3},
    observation:embedded,standalone:'false'}).healthy,false);
});

test('RISC Zero upstream health fails closed for every identity or emergency-stop fault',()=>{
  const changes=[
    o=>{o.extra=true;},o=>{o.riscZeroVerifier.extra=true;},o=>{o.riscZeroEmergencyStop.extra=true;},
    o=>{delete o.riscZeroVerifier.version;},o=>{delete o.riscZeroEmergencyStop.verifier;},
    o=>{o.chainId='31337';},o=>{o.chainId=1;},o=>{o.genesisBlockHash=hash('99');},
    o=>{o.finalizedBlockNumber='invalid';},
    o=>{o.finalizedBlockNumber=null;},o=>{o.finalizedBlockNumber=false;},
    o=>{o.finalizedBlockNumber='';},o=>{o.finalizedBlockNumber=' ';},
    o=>{o.finalizedBlockNumber='0x016e3600';},o=>{o.finalizedBlockNumber='024000000';},
    o=>{o.finalizedBlockNumber='9'.repeat(100000);},
    o=>{o.finalizedBlockNumber=(1n<<64n).toString();},
    o=>{o.finalizedBlockNumber=24000000;},o=>{o.finalizedBlockHash=hash('00');},
    o=>{o.snapshotBlockHashAfter=hash('22');},o=>{delete o.snapshotBlockHashAfter;},
    o=>{o.riscZeroVerifier.address=address(1);},o=>{o.riscZeroVerifier.codeHash=hash('22');},
    o=>{o.riscZeroVerifier.selector='0x01020304';},o=>{o.riscZeroVerifier.selector=0x73c457ba;},
    o=>{o.riscZeroVerifier.selector=PINNED_RISC0_MAINNET_V3.verifier_selector.toUpperCase();},
    o=>{o.riscZeroVerifier.version='other';},
    o=>{o.riscZeroEmergencyStop.address=address(2);},o=>{o.riscZeroEmergencyStop.codeHash=hash('33');},
    o=>{o.riscZeroEmergencyStop.verifier=address(3);},o=>{o.riscZeroEmergencyStop.paused=true;},
    o=>{delete o.riscZeroEmergencyStop.paused;},
  ];
  for(const change of changes) {
    const value=observation(); change(value);
    const report=assessRiscZeroMainnetHealth({reference:{...PINNED_RISC0_MAINNET_V3},observation:value});
    assert.equal(report.healthy,false,JSON.stringify(value));
    assert(report.blockerCount>0);
  }
  const changedReference={...PINNED_RISC0_MAINNET_V3,emergency_stop_wrapper_address:address(4)};
  assert.equal(assessRiscZeroMainnetHealth({reference:changedReference,observation:observation()}).healthy,false);
});
