import test from 'node:test';
import assert from 'node:assert/strict';
import {parseSubmissionHashBytes} from '../../sdk/deployment-text-evidence.mjs';

const hash='0x'+'ab'.repeat(32);
test('submission hash evidence accepts exactly one lowercase hash line',()=>{
  assert.equal(parseSubmissionHashBytes(Buffer.from(`${hash}\n`)),hash);
});

test('submission hash evidence rejects alternate text framing',()=>{
  for(const value of [hash,`${hash}\r\n`,`${hash}\n\n`,` ${hash}\n`,`${hash} \n`,
    `${hash.toUpperCase()}\n`,`0x${'ab'.repeat(31)}\n`,`0x${'gg'.repeat(32)}\n`]) {
    assert.throws(()=>parseSubmissionHashBytes(Buffer.from(value)));
  }
  assert.throws(()=>parseSubmissionHashBytes(new Uint8Array(Buffer.from(`${hash}\n`))));
});
