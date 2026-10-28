function quantity(value,label) {
  if(typeof value!=='string'||value.length>78
      ||(!/^(0|[1-9][0-9]*)$/.test(value)&&!/^0x(0|[1-9a-f][0-9a-f]{0,63})$/.test(value))) {
    throw new Error(`${label} is not a canonical quantity`);
  }
  const parsed=BigInt(value);
  if(parsed>=1n<<256n) throw new Error(`${label} exceeds uint256`);
  return parsed;
}
export function validatePilotReceiptCost({gasUsed,effectiveGasPrice,maximumCost}) {
  const gas=quantity(gasUsed,'gasUsed'),price=quantity(effectiveGasPrice,'effectiveGasPrice');
  const maximum=quantity(maximumCost,'maximumCost'),actual=gas*price;
  if(gas===0n||price===0n||maximum===0n||actual>maximum) throw new Error('pilot receipt gas cost exceeds signed bound');
  return {gasUsed:gas.toString(),effectiveGasPrice:price.toString(),actualCost:actual.toString(),maximumCost:maximum.toString()};
}
