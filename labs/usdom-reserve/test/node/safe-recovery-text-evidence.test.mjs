import test from 'node:test';
import assert from 'node:assert/strict';
import {parseSafeRecoveryRawTransactionBytes} from '../../sdk/safe-recovery-text-evidence.mjs';

test('Safe recovery raw transaction framing accepts one canonical lowercase LF line',()=>{
  assert.equal(parseSafeRecoveryRawTransactionBytes(Buffer.from('0x02ab\n')),'0x02ab');
});

test('Safe recovery raw transaction framing rejects alternate text encodings',()=>{
  for(const value of [
    '0x02ab','0x02ab\r\n','0x02ab\n\n',' 0x02ab\n','0x02ab \n','0X02ab\n',
    '0x02AB\n','0x02ag\n','0xabc\n','0x\n',
  ]) assert.throws(()=>parseSafeRecoveryRawTransactionBytes(Buffer.from(value)),/framing/);
  assert.throws(()=>parseSafeRecoveryRawTransactionBytes(Buffer.from([0xff,0x0a])),/UTF-8/);
});
