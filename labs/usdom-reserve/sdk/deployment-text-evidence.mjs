export function parseSubmissionHashBytes(bytes) {
  if(!Buffer.isBuffer(bytes)||bytes.length!==67) throw new Error('submission hash framing is invalid');
  const text=bytes.toString('ascii');
  if(!/^0x[0-9a-f]{64}\n$/.test(text)) throw new Error('submission hash framing is invalid');
  return text.slice(0,-1);
}
