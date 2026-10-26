import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';

const cases=[
  {
    name:'checkpoint finalized transaction reference',
    file:'../../scripts/write-checkpoint-finalized-transaction-reference.sh',
    sidecar:'install-private-file-immutable-stdin.mjs" "$REFERENCE_SHA"',
    completion:'install-private-file-immutable-stdin.mjs" "$REFERENCE"',
    recovery:/Existing checkpoint transaction-reference hash differs from rebuilt output/,
    sidecarReadback:/cmp -s "\$TEMPORARY\/reference\.sha256" "\$REFERENCE_SHA"/,
    completionReadback:/cmp -s "\$TEMPORARY\/reference\.json" "\$REFERENCE"/,
  },
  {
    name:'checkpoint bootstrap ratification request',
    file:'../../scripts/write-checkpoint-bootstrap-ratification-request.sh',
    sidecar:'install-private-file-immutable-stdin.mjs" "$SHA"',
    completion:'install-private-file-immutable-stdin.mjs" --json "$REQUEST"',
    recovery:/Existing ratification-request hash differs from rebuilt output/,
    sidecarReadback:/cmp -s "\$TEMPORARY\/request\.sha256" "\$SHA"/,
    completionReadback:/cmp -s "\$TEMPORARY\/request\.json" "\$REQUEST"/,
  },
  {
    name:'checkpoint bootstrap ratification signature',
    file:'../../scripts/sign-checkpoint-bootstrap-ratification.sh',
    sidecar:'install-private-file-immutable-stdin.mjs" "$SIGNATURE_SHA"',
    completion:'install-private-file-immutable-stdin.mjs" "$SIGNATURE"',
    recovery:/Existing ratification-signature hash differs from rebuilt signature/,
    sidecarReadback:/signature-sha\.installed\.txt/,
    completionReadback:/signature\.installed\.hex/,
  },
];

test('all proof-to-Ethereum create-once artifact/sidecar pairs are crash-retryable and completion-last',async()=>{
  assert.equal(cases.length,3,'update the explicit inventory when a new pair is introduced');
  for(const item of cases) {
    const source=await readFile(new URL(item.file,import.meta.url),'utf8');
    const sidecar=source.lastIndexOf(item.sidecar);
    const completion=source.lastIndexOf(item.completion);
    assert.ok(sidecar>=0,`${item.name}: sidecar install missing`);
    assert.ok(completion>sidecar,`${item.name}: completion must be installed last`);
    assert.match(source,item.recovery,`${item.name}: authenticated crash retry missing`);
    assert.match(source,item.sidecarReadback,`${item.name}: sidecar readback missing`);
    assert.match(source,item.completionReadback,`${item.name}: completion readback missing`);
  }
});
