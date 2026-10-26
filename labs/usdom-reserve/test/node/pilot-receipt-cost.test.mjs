import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {validatePilotReceiptCost} from '../../sdk/pilot-receipt-cost.mjs';
test('receipt cost is exact and cannot exceed signed maximum',()=>{
  assert.deepEqual(validatePilotReceiptCost({gasUsed:'0x5208',effectiveGasPrice:'0x3b9aca00',maximumCost:'50000000000000'}),
    {gasUsed:'21000',effectiveGasPrice:'1000000000',actualCost:'21000000000000',maximumCost:'50000000000000'});
  for(const value of [{gasUsed:'0',effectiveGasPrice:'1',maximumCost:'1'},
    {gasUsed:'2',effectiveGasPrice:'3',maximumCost:'5'},
    {gasUsed:'0x00',effectiveGasPrice:'1',maximumCost:'2'},
    {gasUsed:'01',effectiveGasPrice:'1',maximumCost:'2'},
    {gasUsed:'1',effectiveGasPrice:'1',maximumCost:'0'}]) assert.throws(()=>validatePilotReceiptCost(value));
});
test('both executors bind receipt gas cost into finality evidence',()=>{
  for(const file of ['execute-closed-mainnet-deposit.sh','execute-closed-mainnet-redemption.sh']) {
    const source=readFileSync(new URL(`../../scripts/${file}`,import.meta.url),'utf8');
    assert.match(source,/check-pilot-receipt-cost\.mjs/); assert.match(source,/effectiveGasPrice/);
    assert.match(source,/actualCost/); assert.match(source,/maximumCost/);
  }
});
