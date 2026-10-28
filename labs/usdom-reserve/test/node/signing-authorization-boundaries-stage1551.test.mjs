import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {Wallet,Signature} from 'ethers';
import {domain,burnTypes,quorumSignatures} from '../../sdk/reserve.mjs';

const reserve='0x'+'9'.repeat(40),h=n=>'0x'+n.repeat(64);
const burn={burnId:h('1'),requestId:h('2'),recipient:'0x'+'3'.repeat(40),amount:'1',
  domDomain:h('4'),height:'1',blockHash:h('5'),epoch:'1',validUntil:'2'};

test('burn quorum is domain-separated and rejects noncanonical/high-s signatures',async()=>{
  const wallets=[Wallet.createRandom(),Wallet.createRandom(),Wallet.createRandom()];
  const signatures=await Promise.all(wallets.map(w=>w.signTypedData(domain('1',reserve),burnTypes,burn)));
  assert.equal(quorumSignatures({chainId:'1',reserve,burn,signatures,notaries:wallets.map(w=>w.address),threshold:3}).length,3);
  assert.throws(()=>quorumSignatures({chainId:'2',reserve,burn,signatures,notaries:wallets.map(w=>w.address),threshold:3}));
  const parsed=Signature.from(signatures[0]),highS='0x'+((1n<<256n)-BigInt(parsed.s)).toString(16).padStart(64,'0');
  const malleated=`${parsed.r}${highS.slice(2)}${parsed.v===27?'1c':'1b'}`;
  assert.throws(()=>quorumSignatures({chainId:'1',reserve,burn,signatures:[malleated,...signatures.slice(1)],notaries:wallets.map(w=>w.address),threshold:3}));
});

test('reserve resume separates Safe signing, payer signing and broadcast authorization',async()=>{
  const source=await readFile(new URL('../../scripts/execute-reserve-resume.sh',import.meta.url),'utf8');
  const safeReview=source.indexOf('AUTHORIZE REVIEW SAFE EIP712 step=schedule');
  const safeSign1=source.indexOf('AUTORIZO ASSINAR SAFE RESUME schedule OWNER 1');
  const firstHardwareSignature=source.indexOf('wallet sign --no-hash');
  assert.ok(safeReview>=0&&safeReview<safeSign1&&safeSign1<firstHardwareSignature);
  for(const field of ['chainId=1','verifyingContract=$governance','safeNonce=$nonce','to=$reserve','valueWei=0','calldataHash=','safeTxHash=']) assert.ok(source.includes(field));
  assert.match(source,/ownersByRole\.governance\[\][\s\S]*Signature,recoverAddress,getAddress/);
  const outerReview=source.indexOf('AUTHORIZE REVIEW action=$step');
  const payerSign=source.indexOf('AUTORIZO ASSINAR RETOMADA $step AUTH $authorization_hash');
  const makeTx=source.indexOf('prepare-ledger-eip1559-transaction.mjs "$private_input"',payerSign);
  const transmit=source.indexOf('AUTORIZO TRANSMITIR RETOMADA $step TX ${expected_txhash,,}');
  const publish=source.indexOf('publish-private-raw-transaction.mjs "$raw"',transmit);
  assert.ok(outerReview>=0&&outerReview<payerSign&&payerSign<makeTx&&makeTx<transmit&&transmit<publish);
  for(const token of ['signer=$signer2','nonce=$payer_nonce','target=$target','calldataHash=$exec_data_hash','"$payer_nonce" "$gas_limit"','--block finalized']) assert.ok(source.includes(token),token);
});

test('Safe deployment delegates gas-only signing through an exact external envelope',async()=>{
  const source=await readFile(new URL('../../scripts/execute-safe-control-deployment.sh',import.meta.url),'utf8');
  const make=source.indexOf('prepare-safe-control-deployment-relayer-envelope.mjs');
  const wait=source.indexOf('Envelope gas-only do relayer instalado em',make);
  const validate=source.indexOf('check-safe-control-deployment-relayer-raw.mjs');
  const transmit=source.indexOf('AUTORIZO TRANSMITIR SAFE $role NONCE $nonce',validate);
  assert.ok(make>=0&&wait>make&&validate>=0&&transmit>=0);
  assert.match(source,/safe-control-deployment-relayer-policy\.json/);
  assert.match(source,/safe-control-deployment-relayer-keystore\.json/);
  assert.doesNotMatch(source,/AUTORIZO ASSINAR SAFE|wallet sign|--ledger|OneKey/);
});

test('DOM mining remains separately authorized and cannot be implied by proof/signing',async()=>{
  const source=await readFile(new URL('../../scripts/mine-closed-mainnet-burn-block.mjs',import.meta.url),'utf8');
  assert.match(source,/AUTORIZO MINERAR UM BLOCO USDOM/);
  assert.match(source,/scanInclusion\(existing,token\)/);
  assert.doesNotMatch(source,/AUTORIZO (?:ASSINAR|TRANSMITIR).*AUTORIZO MINERAR/s);
});
