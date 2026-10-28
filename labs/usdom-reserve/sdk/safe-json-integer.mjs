/** Convert an externally supplied unsigned integer to a JSON number without
 * allowing JavaScript's binary64 representation to change its value. */
export function safeJsonUint(value,label,{bits=64}={}) {
  if(!Number.isSafeInteger(bits)||bits<1||bits>256) throw new Error('invalid integer bit bound');
  if(typeof value==='number') {
    if(!Number.isSafeInteger(value)||value<0||Object.is(value,-0)) {
      throw new Error(`${label} is not an unsigned safe JSON integer`);
    }
  } else if(typeof value==='string') {
    if(!/^(?:0|[1-9][0-9]*|0x(?:0|[1-9a-f][0-9a-f]*))$/.test(value)) {
      throw new Error(`${label} is not a canonical unsigned integer`);
    }
  } else if(typeof value!=='bigint'||value<0n) {
    throw new Error(`${label} is not an unsigned integer`);
  }
  const parsed=BigInt(value);
  if(parsed>=(1n<<BigInt(bits))) throw new Error(`${label} exceeds uint${bits}`);
  if(parsed>BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${label} cannot be represented exactly as a JSON number`);
  }
  return Number(parsed);
}
