import {
  Signature,
  Transaction,
  TypedDataEncoder,
  getAddress,
  recoverAddress,
  verifyTypedData,
} from 'ethers';

const MAINNET_CHAIN_ID = 1n;
const PATH = /^m\/44'\/60'\/(0|[1-9][0-9]{0,8})'\/0\/(0|[1-9][0-9]{0,8})$/;
const HASH = /^0x[0-9a-f]{64}$/;
const fail = message => { throw new Error(message); };

function canonicalPath(path) {
  if (typeof path !== 'string' || !PATH.test(path)) fail('OneKey derivation path is invalid');
  return path;
}

function canonicalAddress(address, label) {
  if (typeof address !== 'string') fail(`${label} is invalid`);
  const canonical = getAddress(address);
  if (canonical !== address) fail(`${label} is noncanonical`);
  return canonical;
}

function payload(result, method) {
  if (!result || result.success !== true || !result.payload || typeof result.payload !== 'object') {
    fail(`OneKey ${method} failed`);
  }
  return result.payload;
}

function method(device, name) {
  if (!device || typeof device[name] !== 'function') fail(`OneKey ${name} is unavailable`);
  return device[name].bind(device);
}

function exactHash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) fail(`${label} is invalid`);
  return value;
}

function deviceIdentifier(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(value)) fail(`${label} is invalid`);
  return value;
}

function deviceSignature(response, methodName) {
  const signed = payload(response, methodName);
  if (Object.keys(signed).sort().join(',') !== 'r,s,v') fail(`OneKey ${methodName} response is ambiguous`);
  if (typeof signed.r !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(signed.r)
    || typeof signed.s !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(signed.s)
    || !['0x0', '0x1'].includes(signed.v)) {
    fail(`OneKey ${methodName} signature is noncanonical`);
  }
  const r = signed.r.toLowerCase(), s = signed.s.toLowerCase(), yParity = Number(BigInt(signed.v));
  const signature = Signature.from({yParity, r, s});
  if (signature.r !== r || signature.s !== s || signature.yParity !== yParity) {
    fail(`OneKey ${methodName} signature is noncanonical`);
  }
  return signature;
}

function transactionRequest(transaction, path) {
  const quantity=value=>`0x${value.toString(16)}`;
  return Object.freeze({
    path,
    useEmptyPassphrase: true,
    transaction: Object.freeze({
      // The pinned OneKey EVM API represents contract creation with an empty
      // destination string; the canonical Ethereum transaction retains null.
      to: transaction.to ?? '',
      value: quantity(transaction.value),
      data: transaction.data,
      chainId: Number(transaction.chainId),
      nonce: quantity(BigInt(transaction.nonce)),
      gasLimit: quantity(transaction.gasLimit),
      maxFeePerGas: quantity(transaction.maxFeePerGas),
      maxPriorityFeePerGas: quantity(transaction.maxPriorityFeePerGas),
    }),
  });
}

function validateUnsigned(serialized, expectedHash) {
  if (typeof serialized !== 'string' || !/^0x[0-9a-f]+$/.test(serialized)) fail('unsigned transaction is noncanonical');
  const transaction = Transaction.from(serialized);
  if (transaction.type !== 2 || transaction.chainId !== MAINNET_CHAIN_ID || transaction.signature !== null
    || transaction.accessList.length !== 0
    || transaction.unsignedSerialized !== serialized || transaction.unsignedHash !== expectedHash) {
    fail('unsigned transaction binding mismatch');
  }
  return transaction;
}

async function displayedAddress(device, connectId, deviceId, path, expectedAddress) {
  const response = payload(await method(device, 'evmGetAddress')(connectId, deviceId, {
    path,
    chainId: 1,
    useEmptyPassphrase: true,
    showOnOneKey: true,
  }), 'evmGetAddress');
  const address = canonicalAddress(response.address, 'OneKey address');
  if (address !== expectedAddress) fail('OneKey address binding mismatch');
  return address;
}

export function createOneKeyEthereumMainnetBoundary({device, connectId, deviceId, derivationPath, expectedAddress} = {}) {
  const connection = deviceIdentifier(connectId, 'OneKey connectId');
  const identity = deviceIdentifier(deviceId, 'OneKey deviceId');
  const path = canonicalPath(derivationPath);
  const address = canonicalAddress(expectedAddress, 'expected OneKey address');
  // Resolve all three official operations up front. There is deliberately no
  // alternate signer fallback in this production boundary.
  method(device, 'evmGetAddress');
  method(device, 'evmSignTransaction');
  method(device, 'evmSignTypedData');

  return Object.freeze({
    derivationPath: path,
    expectedAddress: address,

    async confirmAddress() {
      return displayedAddress(device, connection, identity, path, address);
    },

    async signTransaction({unsignedSerialized, unsignedHash} = {}) {
      const expectedHash = exactHash(unsignedHash, 'unsigned transaction hash');
      const transaction = validateUnsigned(unsignedSerialized, expectedHash);
      await displayedAddress(device, connection, identity, path, address);
      const signature = deviceSignature(await method(device, 'evmSignTransaction')(
        connection, identity, transactionRequest(transaction, path),
      ), 'evmSignTransaction');
      if (getAddress(recoverAddress(expectedHash, signature)) !== address) {
        fail('OneKey transaction signer mismatch');
      }
      transaction.signature = signature;
      const rawTransaction = transaction.serialized;
      const reparsed = Transaction.from(rawTransaction);
      if (reparsed.serialized !== rawTransaction || reparsed.unsignedHash !== expectedHash
        || reparsed.from !== address || reparsed.chainId !== MAINNET_CHAIN_ID) {
        fail('OneKey signed transaction round trip mismatch');
      }
      return Object.freeze({address, derivationPath: path, unsignedHash: expectedHash, rawTransaction});
    },

    async signTypedData({domain, types, value, digest} = {}) {
      const expectedDigest = exactHash(digest, 'typed-data digest');
      if (!domain || typeof domain !== 'object' || Array.isArray(domain)
        || !types || typeof types !== 'object' || Array.isArray(types)
        || !value || typeof value !== 'object' || Array.isArray(value)
        || typeof value.primaryType !== 'undefined') fail('typed data is invalid');
      const primaryTypes=Object.keys(types).filter(name=>name!=='EIP712Domain');
      const domainFields=[['name','string'],['version','string'],['chainId','uint256'],['verifyingContract','address'],['salt','bytes32']]
        .filter(([name])=>Object.hasOwn(domain,name)).map(([name,type])=>({name,type}));
      if(!Array.isArray(types.EIP712Domain)||primaryTypes.length===0
          ||Object.keys(domain).some(name=>!['name','version','chainId','verifyingContract','salt'].includes(name))
          ||JSON.stringify(types.EIP712Domain)!==JSON.stringify(domainFields)) fail('typed data types are invalid');
      const signingTypes=Object.fromEntries(primaryTypes.map(name=>[name,types[name]]));
      const primaryType=TypedDataEncoder.from(signingTypes).primaryType;
      if (BigInt(domain.chainId) !== MAINNET_CHAIN_ID || TypedDataEncoder.hash(domain, signingTypes, value) !== expectedDigest) {
        fail('typed-data binding mismatch');
      }
      await displayedAddress(device, connection, identity, path, address);
      const response=payload(await method(device, 'evmSignTypedData')(connection, identity, {
        path,
        useEmptyPassphrase: true,
        data:{types,primaryType,domain,message:value},
        metamaskV4Compat: true,
        chainId: 1,
      }), 'evmSignTypedData');
      if(Object.keys(response).sort().join(',')!=='address,signature'
          ||canonicalAddress(response.address,'OneKey typed-data address')!==address
          ||typeof response.signature!=='string'||!/^[0-9a-f]{130}$/.test(response.signature)) {
        fail('OneKey evmSignTypedData response is noncanonical');
      }
      const signature=Signature.from(`0x${response.signature}`);
      if(signature.serialized!==`0x${response.signature}`
          ||getAddress(verifyTypedData(domain, signingTypes, value, signature)) !== address) {
        fail('OneKey typed-data signer mismatch');
      }
      return Object.freeze({address, derivationPath: path, digest: expectedDigest, signature: signature.serialized});
    },
  });
}

