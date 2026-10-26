export const MAX_ETHEREUM_QUANTITY_UINT64=(1n<<64n)-1n;

export function canonicalEthereumQuantity(value,{maximum=MAX_ETHEREUM_QUANTITY_UINT64}={}) {
  if(typeof value!=='string'||!/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(value)) {
    throw new Error('Ethereum quantity must be canonical lowercase hex');
  }
  if(typeof maximum!=='bigint'||maximum<0n) throw new Error('quantity maximum is invalid');
  const quantity=BigInt(value);
  if(quantity>maximum) throw new Error('Ethereum quantity exceeds the supported bound');
  return quantity.toString();
}

export const MAX_UINT256=(1n<<256n)-1n;
export function canonicalUnsignedDecimal(value,{maximum=MAX_UINT256}={}) {
  if(typeof value!=='string'||!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new Error('unsigned decimal must be canonical');
  }
  if(typeof maximum!=='bigint'||maximum<0n) throw new Error('decimal maximum is invalid');
  const quantity=BigInt(value);
  if(quantity>maximum) throw new Error('unsigned decimal exceeds the supported bound');
  return value;
}
