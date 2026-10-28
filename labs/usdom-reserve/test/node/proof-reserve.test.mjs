import test from 'node:test';
import assert from 'node:assert/strict';
import {Wallet} from 'ethers';
import {
  BURN_INTENT_TYPEHASH,
  BURN_DEBT_TYPEHASH,
  BURN_STATEMENT_TYPEHASH,
  PRIVATE_BURN_ID_TYPEHASH,
  burnIntentHash,
  finalizedBurnDebtHash,
  derivePrivateBurnId,
  finalizedBurnFields,
  finalizedBurnStatementHash,
  normalizeFinalizedBurn,
  reserveDepositId,
} from '../../sdk/proof-reserve.mjs';

const h = n => '0x' + n.toString(16).padStart(64, '0');
const repeated = (byte, bytes) => '0x' + byte.toString(16).padStart(2, '0').repeat(bytes);
const reserve = '0x0000000000000000000000000000000000001234';
const activationScheduleCommitment=h(11);
const burn = {
  burnId:h(1), requestId:h(2), recipient:new Wallet('0x'+'11'.repeat(32)).address,
  amount:'9007199254740993', domDomain:h(3), height:'4', blockHash:h(5), stateRoot:h(6),
  finalityBeaconSlot:'7', validUntil:'1800600000',
};

test('deposit identity matches Solidity ABI encoding and binds every domain field', () => {
  const input={chainId:'31337',reserve:'0x0000000000000000000000000000000000001234',
    funder:'0x0000000000000000000000000000000000005678',salt:repeated(0xab,32)};
  const base=reserveDepositId(input);
  assert.equal(base,'0xc72de19b4817ee2b6d6085948efda1b1b419061229927cfd5b4aff8f5465e504');
  assert.notEqual(base,reserveDepositId({...input,chainId:'31338'}));
  assert.notEqual(base,reserveDepositId({...input,reserve:input.funder}));
  assert.notEqual(base,reserveDepositId({...input,funder:input.reserve}));
  assert.notEqual(base,reserveDepositId({...input,salt:repeated(0xac,32)}));
});

test('proof statement preserves uint64 precision and rejects noncanonical fields', () => {
  assert.equal(normalizeFinalizedBurn(burn).amount, 9007199254740993n);
  assert.match(BURN_STATEMENT_TYPEHASH, /^0x[0-9a-f]{64}$/);
  assert.equal(BURN_STATEMENT_TYPEHASH,'0xb4a224b119278936bec16ab7cf63f13d2cc130395834d17a30335b9158062ced');
  assert.match(BURN_INTENT_TYPEHASH, /^0x[0-9a-f]{64}$/);
  assert.equal(BURN_INTENT_TYPEHASH, '0xf1d5a150f09a125f5ab99669e765334c3d22034c98b84d0f903a900320b7f446');
  assert.throws(() => normalizeFinalizedBurn({...burn, extra:true}));
  assert.throws(() => normalizeFinalizedBurn({...burn, amount:0n}));
  assert.throws(() => normalizeFinalizedBurn({...burn, stateRoot:h(0)}));
});

test('native burn intent binds payout fields but excludes later finality identity', () => {
  const base = burnIntentHash({chainId:'31337', reserve, burn});
  for (const field of ['burnId', 'requestId', 'recipient', 'amount', 'domDomain', 'validUntil']) {
    const changed = {...burn};
    changed[field] = field === 'recipient' ? reserve : field.endsWith('Id') || field === 'domDomain' ? h(99) : '99';
    assert.notEqual(base, burnIntentHash({chainId:'31337', reserve, burn:changed}), field);
  }
  for (const field of ['height', 'blockHash', 'stateRoot', 'finalityBeaconSlot']) {
    const changed = {...burn, [field]:field === 'height' || field === 'finalityBeaconSlot' ? '99' : h(99)};
    assert.equal(base, burnIntentHash({chainId:'31337', reserve, burn:changed}), field);
  }
  assert.notEqual(base, burnIntentHash({chainId:'31338', reserve, burn}));
  assert.notEqual(base, burnIntentHash({chainId:'31337', reserve:burn.recipient, burn}));
});

test('native burn intent matches the Rust canonical ABI vector', () => {
  const nativeVector={
    burnId:'0xd0b8ffc2dc9668fc6d73bee43ebc979ed69e5cd0d2d8d1656d753539816b762b',
    requestId:repeated(0x09,32),recipient:repeated(0x08,20),amount:'250',domDomain:repeated(0x11,32),
    height:'1',blockHash:h(1),stateRoot:h(2),finalityBeaconSlot:'1',validUntil:'1800600000',
  };
  assert.equal(
    burnIntentHash({chainId:'31337',reserve:repeated(0x66,20),burn:nativeVector}),
    '0x4f9a7214fb6b5701fe358a82952462bc172f220721a72b264e4b738558a1d842',
  );
});

test('proof statement binds every burn field, chain and reserve', () => {
  const input={chainId:'31337',reserve,activationScheduleCommitment,burn};
  const base = finalizedBurnStatementHash(input);
  assert.equal(base,'0x1016275e2148a768d3ff2afca10d14e8b74d7c0d8ac0a3b2d2c3758f81510318');
  assert.notEqual(base, finalizedBurnStatementHash({...input,chainId:'31338'}));
  assert.notEqual(base, finalizedBurnStatementHash({...input,reserve:burn.recipient}));
  assert.notEqual(base, finalizedBurnStatementHash({...input,activationScheduleCommitment:h(13)}));
  for (const field of finalizedBurnFields) {
    const changed = {...burn};
    changed[field.name] = field.type === 'address' ? reserve : field.type === 'bytes32' ? h(99) : '99';
    assert.notEqual(base, finalizedBurnStatementHash({...input,burn:changed}), field.name);
  }
});

test('proved debt permits only a freshly proved finality-slot renewal', () => {
  const input={chainId:'31337',reserve,activationScheduleCommitment,burn};
  const base = finalizedBurnDebtHash(input);
  assert.match(BURN_DEBT_TYPEHASH, /^0x[0-9a-f]{64}$/);
  assert.equal(base, finalizedBurnDebtHash({...input,burn:{...burn,finalityBeaconSlot:'99'}}));
  for (const field of finalizedBurnFields.filter(({name}) => name !== 'finalityBeaconSlot')) {
    const changed = {...burn};
    changed[field.name] = field.type === 'address' ? reserve : field.type === 'bytes32' ? h(99) : '99';
    assert.notEqual(base, finalizedBurnDebtHash({...input,burn:changed}), field.name);
  }
  assert.notEqual(base, finalizedBurnDebtHash({...input,chainId:'31338'}));
  assert.notEqual(base, finalizedBurnDebtHash({...input,reserve:burn.recipient}));
  assert.notEqual(base, finalizedBurnDebtHash({...input,activationScheduleCommitment:h(13)}));
});

test('private burn id matches native consensus vector and binds authenticated nullifiers', () => {
  const input = {
    domDomain: repeated(0x11, 32),
    privacyPolicyHash: '0xd66687e30a3540932de46fc6a6c9d151d1a46d5f2e0e0fcd2bca568b05bad90c',
    verifierConfigHash: repeated(0x45, 32),
    chainId: 31337n,
    reserve: repeated(0x66, 20),
    recipient: repeated(0x08, 20),
    amount: 250n,
    validUntil: 1_800_600_000n,
    nullifiers: [repeated(0x06, 32)],
  };
  assert.match(PRIVATE_BURN_ID_TYPEHASH, /^0x[0-9a-f]{64}$/);
  assert.equal(
    derivePrivateBurnId(input),
    '0xd0b8ffc2dc9668fc6d73bee43ebc979ed69e5cd0d2d8d1656d753539816b762b',
  );
  for (const field of ['domDomain','privacyPolicyHash','verifierConfigHash','chainId','reserve','recipient','amount','validUntil']) {
    const changed = {...input, [field]: field === 'chainId' || field === 'amount' || field === 'validUntil'
      ? BigInt(input[field]) + 1n
      : field === 'reserve' || field === 'recipient' ? repeated(0x77, 20) : repeated(0x77, 32)};
    assert.notEqual(derivePrivateBurnId(input), derivePrivateBurnId(changed), field);
  }
  assert.notEqual(derivePrivateBurnId(input), derivePrivateBurnId({...input, nullifiers:[repeated(0x07, 32)]}));
  assert.throws(() => derivePrivateBurnId({...input, nullifiers:[]}));
  assert.throws(() => derivePrivateBurnId({...input, nullifiers:[repeated(0xff, 32)]}));
  assert.throws(() => derivePrivateBurnId({...input, nullifiers:[repeated(0x07, 32), repeated(0x06, 32)]}));
});
