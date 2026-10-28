import {getAddress, Signature, TypedDataEncoder, verifyTypedData} from 'ethers';

export const burnTypes = Object.freeze({Burn: Object.freeze([
  ['burnId','bytes32'], ['requestId','bytes32'], ['recipient','address'], ['amount','uint64'],
  ['domDomain','bytes32'], ['height','uint64'], ['blockHash','bytes32'], ['epoch','uint64'], ['validUntil','uint64'],
].map(([name,type]) => Object.freeze({name,type})))});
const zero = '0x' + '00'.repeat(32);
export function uint(value, bits = 64) {
  if(!Number.isInteger(bits)||bits<1||bits>256) throw new Error('integer width out of range');
  const maximum=1n<<BigInt(bits);
  const maximumDigits=(maximum-1n).toString().length;
  if (typeof value !== 'bigint' && !(typeof value === 'string'&&value.length<=maximumDigits
      && /^(0|[1-9][0-9]*)$/.test(value))) {
    throw new Error('integers must be bigint or canonical decimal strings');
  }
  const n = BigInt(value);
  if (n < 0n || n >= maximum) throw new Error('integer out of range');
  return n;
}
function hash(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(value) || value.toLowerCase() === zero) {
    throw new Error('nonzero bytes32 required');
  }
  return value.toLowerCase();
}
export function domain(chainId, address) {
  const id = uint(chainId, 256);
  if (id === 0n) throw new Error('zero chain id');
  const verifyingContract = getAddress(address);
  if (BigInt(verifyingContract) === 0n) throw new Error('zero reserve');
  return {name:'USDOMReserve', version:'3', chainId:id, verifyingContract};
}
export function normalizeBurn(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('burn object required');
  const names = burnTypes.Burn.map(x => x.name);
  if (Object.keys(input).length !== names.length || Object.keys(input).some(x => !names.includes(x))) {
    throw new Error('exact Burn fields required');
  }
  const result = {};
  for (const {name,type} of burnTypes.Burn) {
    result[name] = type === 'uint64' ? uint(input[name]) : type === 'bytes32' ? hash(input[name]) : getAddress(input[name]);
    if ((type === 'uint64' || type === 'address') && BigInt(result[name]) === 0n) throw new Error(`${name} is zero`);
  }
  return result;
}
export function digest(chainId, address, input) {
  return TypedDataEncoder.hash(domain(chainId, address), burnTypes, normalizeBurn(input));
}
/** Pure signature assembly. Does not establish remote burn validity or finality. */
export function quorumSignatures({chainId, reserve, burn, signatures, notaries, threshold}) {
  if (!Number.isInteger(threshold) || notaries.length < 3 || notaries.length > 16
      || threshold <= Math.floor(notaries.length * 2 / 3) || threshold > notaries.length
      || signatures.length !== threshold) throw new Error('invalid quorum size');
  const allowed = new Set(notaries.map(a => getAddress(a).toLowerCase()));
  if (allowed.size !== notaries.length || [...allowed].some(a => BigInt(a) === 0n)) throw new Error('invalid notary set');
  const d = domain(chainId, reserve), b = normalizeBurn(burn);
  const recovered = signatures.map(signature => {
    if (typeof signature !== 'string' || !/^0x[0-9a-f]{130}$/.test(signature)
        || Signature.from(signature).serialized !== signature) throw new Error('canonical 65-byte signature required');
    const signer = verifyTypedData(d, burnTypes, b, signature).toLowerCase();
    if (!allowed.has(signer)) throw new Error('unknown signer');
    return {signer, signature};
  }).sort((a,b) => BigInt(a.signer) < BigInt(b.signer) ? -1 : 1);
  if (new Set(recovered.map(x => x.signer)).size !== threshold) throw new Error('duplicate signer');
  return recovered.map(x => x.signature);
}
