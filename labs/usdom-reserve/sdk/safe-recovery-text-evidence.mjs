export function parseSafeRecoveryRawTransactionBytes(bytes) {
  if(!Buffer.isBuffer(bytes)&&!(bytes instanceof Uint8Array)) {
    throw new Error('Safe recovery raw transaction must be bytes');
  }
  let contents;
  try { contents=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
  catch { throw new Error('Safe recovery raw transaction contains invalid UTF-8'); }
  if(!/^0x[0-9a-f]+\n$/.test(contents)||contents.length%2!==1) {
    throw new Error('Safe recovery raw transaction framing is invalid');
  }
  return contents.slice(0,-1);
}
