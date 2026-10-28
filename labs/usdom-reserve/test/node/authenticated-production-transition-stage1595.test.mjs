import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';

const read=relative=>readFileSync(new URL(`../../${relative}`,import.meta.url),'utf8');

test('technical readiness and real-funds authority are distinct transitions',()=>{
  const core=read('sdk/production-release-core.mjs');
  const prepareCore=read('scripts/prepare-production-release-core-materialization.mjs');
  const coreWriter=read('scripts/materialize-production-release-core.sh');
  assert.match(core,/completeTechnicalProduction=false/);
  assert.match(core,/technical production readiness requires every final artifact binding/);
  assert.match(core,/result\.productionReady=true/);
  assert.match(core,/result\.realFundsAuthorized!==false/);
  assert.match(prepareCore,/completeTechnicalProduction:true/);
  assert.match(coreWriter,/final\)[\s\S]*\.productionReady == true and \.realFundsAuthorized == false/);
});

test('deployment preparation accepts only the technical pre-funds state',()=>{
  const deployment=read('scripts/prepare-mainnet-deployment.mjs');
  assert.match(deployment,/releaseConfig\.productionReady!==true \|\| releaseConfig\.realFundsAuthorized!==false/);
});
