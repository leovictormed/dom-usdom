import {AbiCoder,Interface,getAddress,keccak256} from 'ethers';
import {proofReserveConfigurationFromRelease} from './finalized-burn-submission.mjs';

export const CLOSED_MAINNET_DEPOSIT_SCHEMA='usdom-closed-mainnet-deposit-v1';
export const CLOSED_MAINNET_DEPOSIT_AMOUNT=1_000_000n;
const usdt=getAddress('0xdAC17F958D2ee523a2206206994597C13D831ec7');
const scalarField=BigInt('0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001');
const walletFields=[
  'schema','domDomain','privacyPolicyHash','chainScalar','receivingCommitment',
  'recipientAddress','backupPath',
];
const transactionFields=['name','to','value','method','data','dataKeccak256'];
const packageFields=[
  'schema','releaseConfigSha256','reserveConfigHash','walletIdentitySha256',
  'ethereumChainId','funder','token','reserve','amountBaseUnits','salt',
  'depositId','receivingCommitment','recipientAddress','transactions','broadcastAuthorized',
];
const tokenInterface=new Interface(['function approve(address spender,uint256 amount) returns (bool)']);
const reserveInterface=new Interface([
  'function deposit(uint64 amount,bytes32 salt,bytes32 receivingCommitment) returns (bytes32)',
]);

function exact(value,fields,label) {
  if(!value || typeof value!=='object' || Array.isArray(value)
      || JSON.stringify(Object.keys(value).sort())!==JSON.stringify([...fields].sort())) {
    throw new Error(`exact ${label} fields required`);
  }
}
function bytes32(value,label) {
  if(typeof value!=='string' || !/^0x[0-9a-f]{64}$/.test(value)
      || value==='0x'+'00'.repeat(32)) throw new Error(`${label} must be canonical nonzero bytes32`);
  return value;
}
function rawHash(value,label) {
  if(typeof value!=='string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be a canonical SHA-256 digest`);
  }
  return value;
}
function transaction(name,to,method,data) {
  return {name,to:getAddress(to),value:'0',method,data,dataKeccak256:keccak256(data)};
}

function validateRecipientAddress(recipientAddress,expectedOwner) {
  if(typeof recipientAddress!=='string' || !/^[0-9a-f]{208}$/.test(recipientAddress)) {
    throw new Error('recipientAddress must be canonical USDADR01 bytes');
  }
  const address=Buffer.from(recipientAddress,'hex');
  const owner='0x'+address.subarray(40,72).toString('hex');
  if(address.subarray(0,8).toString('ascii')!=='USDADR01'
      || address.subarray(8,40).every(byte=>byte===0)
      || owner!==expectedOwner
      || address.subarray(72).every(byte=>byte===0)
      || BigInt(owner)>=scalarField) {
    throw new Error('recipientAddress does not reproduce its public deposit commitment');
  }
  return address;
}

export function validateNativeReceivingWalletPublic(wallet) {
  exact(wallet,walletFields,'native receiving-wallet identity');
  if(wallet.schema!=='usdom-native-receiving-wallet-public-v1'
      || typeof wallet.backupPath!=='string' || !wallet.backupPath.startsWith('/')) {
    throw new Error('native receiving-wallet identity metadata is invalid');
  }
  const domain=bytes32(wallet.domDomain,'wallet domDomain');
  bytes32(wallet.privacyPolicyHash,'wallet privacyPolicyHash');
  const chain=bytes32(wallet.chainScalar,'wallet chainScalar');
  const owner=bytes32(wallet.receivingCommitment,'wallet receivingCommitment');
  const address=validateRecipientAddress(wallet.recipientAddress,owner);
  if('0x'+address.subarray(8,40).toString('hex')!==chain) {
    throw new Error('recipientAddress does not reproduce its public deposit commitment');
  }
  return {domain,owner,address:wallet.recipientAddress};
}

export function buildClosedMainnetDepositPackage({
  release,wallet,funder,salt,releaseConfigSha256,walletIdentitySha256,
}) {
  const configuration=proofReserveConfigurationFromRelease(release);
  const publicWallet=validateNativeReceivingWalletPublic(wallet);
  const normalizedFunder=getAddress(funder);
  const normalizedSalt=bytes32(salt,'deposit salt');
  rawHash(releaseConfigSha256,'releaseConfigSha256');
  rawHash(walletIdentitySha256,'walletIdentitySha256');
  if(BigInt(configuration.ethereumChainId)!==1n || getAddress(configuration.token)!==usdt
      || release.productionReady!==true || release.realFundsAuthorized!==true
      || publicWallet.domain!==configuration.domDomain.toLowerCase()
      || BigInt(configuration.maxOutstandingBaseUnits)!==CLOSED_MAINNET_DEPOSIT_AMOUNT
      || BigInt(configuration.outflowCapacityBaseUnitsPerDay)!==CLOSED_MAINNET_DEPOSIT_AMOUNT) {
    throw new Error('closed deposit differs from the authorized exact mainnet release');
  }
  const resetData=tokenInterface.encodeFunctionData('approve',[configuration.reserve,0n]);
  const approveData=tokenInterface.encodeFunctionData(
    'approve',[configuration.reserve,CLOSED_MAINNET_DEPOSIT_AMOUNT],
  );
  const depositData=reserveInterface.encodeFunctionData('deposit',[
    CLOSED_MAINNET_DEPOSIT_AMOUNT,normalizedSalt,publicWallet.owner,
  ]);
  const depositId=keccak256(AbiCoder.defaultAbiCoder().encode(
    ['uint256','address','address','bytes32'],
    [1n,configuration.reserve,normalizedFunder,normalizedSalt],
  ));
  return {
    schema:CLOSED_MAINNET_DEPOSIT_SCHEMA,releaseConfigSha256,
    reserveConfigHash:release.reserveConfigHash.toLowerCase(),walletIdentitySha256,
    ethereumChainId:'1',funder:normalizedFunder,
    token:usdt,reserve:getAddress(configuration.reserve),
    amountBaseUnits:CLOSED_MAINNET_DEPOSIT_AMOUNT.toString(),salt:normalizedSalt,
    depositId,receivingCommitment:publicWallet.owner,recipientAddress:publicWallet.address,
    transactions:[
      transaction('reset-usdt-allowance',usdt,'approve(address,uint256)',resetData),
      transaction('approve-exact-usdt',usdt,'approve(address,uint256)',approveData),
      transaction('deposit-usdt',configuration.reserve,'deposit(uint64,bytes32,bytes32)',depositData),
    ],
    broadcastAuthorized:false,
  };
}

export function validateClosedMainnetDepositPackage(value) {
  exact(value,packageFields,'closed mainnet deposit package');
  if(value.schema!==CLOSED_MAINNET_DEPOSIT_SCHEMA || value.ethereumChainId!=='1'
      || value.amountBaseUnits!==CLOSED_MAINNET_DEPOSIT_AMOUNT.toString()
      || value.broadcastAuthorized!==false || !Array.isArray(value.transactions)
      || value.transactions.length!==3) {
    throw new Error('closed mainnet deposit package metadata is invalid');
  }
  rawHash(value.releaseConfigSha256,'releaseConfigSha256');
  rawHash(value.walletIdentitySha256,'walletIdentitySha256');
  bytes32(value.reserveConfigHash,'reserveConfigHash');
  const funder=getAddress(value.funder),reserve=getAddress(value.reserve);
  if(value.funder!==funder || value.reserve!==reserve || value.token!==usdt) {
    throw new Error('closed mainnet deposit package addresses are not canonical');
  }
  const salt=bytes32(value.salt,'deposit salt');
  const owner=bytes32(value.receivingCommitment,'receivingCommitment');
  validateRecipientAddress(value.recipientAddress,owner);
  const expectedId=keccak256(AbiCoder.defaultAbiCoder().encode(
    ['uint256','address','address','bytes32'],[1n,reserve,funder,salt],
  ));
  if(value.depositId!==expectedId) throw new Error('closed deposit ID is not canonical');
  value.transactions.forEach(item=>exact(item,transactionFields,'closed deposit transaction'));
  const [resetSpender,resetAmount]=tokenInterface.decodeFunctionData(
    'approve',value.transactions[0].data,
  );
  const [approveSpender,approveAmount]=tokenInterface.decodeFunctionData(
    'approve',value.transactions[1].data,
  );
  const [depositAmount,depositSalt,depositOwner]=reserveInterface.decodeFunctionData(
    'deposit',value.transactions[2].data,
  );
  const expected=[
    transaction('reset-usdt-allowance',usdt,'approve(address,uint256)',
      tokenInterface.encodeFunctionData('approve',[reserve,0n])),
    transaction('approve-exact-usdt',usdt,'approve(address,uint256)',
      tokenInterface.encodeFunctionData('approve',[reserve,CLOSED_MAINNET_DEPOSIT_AMOUNT])),
    transaction('deposit-usdt',reserve,'deposit(uint64,bytes32,bytes32)',
      reserveInterface.encodeFunctionData('deposit',[CLOSED_MAINNET_DEPOSIT_AMOUNT,salt,owner])),
  ];
  if(resetSpender!==reserve || resetAmount!==0n || approveSpender!==reserve
      || approveAmount!==CLOSED_MAINNET_DEPOSIT_AMOUNT || depositAmount!==CLOSED_MAINNET_DEPOSIT_AMOUNT
      || depositSalt!==salt || depositOwner!==owner
      || JSON.stringify(value.transactions)!==JSON.stringify(expected)) {
    throw new Error('closed mainnet deposit calldata is not canonical');
  }
  return value;
}
