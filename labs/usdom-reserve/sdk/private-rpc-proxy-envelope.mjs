function exact(value,keys) {
  return value&&typeof value==='object'&&!Array.isArray(value)
    &&JSON.stringify(Object.keys(value).sort())===JSON.stringify([...keys].sort());
}

export function validatePrivateRpcProxyRequest(value,allowedMethods) {
  if(!exact(value,['jsonrpc','id','method','params'])||value.jsonrpc!=='2.0'
      ||!Number.isSafeInteger(value.id)||value.id<0||typeof value.method!=='string'
      ||!allowedMethods?.has(value.method)||!Array.isArray(value.params)) {
    throw new Error('invalid local JSON-RPC request');
  }
  return value;
}

export function validatePrivateRpcProxyResponse(value,expectedId) {
  const result=exact(value,['jsonrpc','id','result']);
  const error=exact(value,['jsonrpc','id','error']);
  if((result===error)||value.jsonrpc!=='2.0'||value.id!==expectedId) {
    throw new Error('invalid upstream JSON-RPC response');
  }
  if(error) {
    const fields=Object.keys(value.error??{}).sort();
    if(!value.error||Array.isArray(value.error)||typeof value.error!=='object'
        ||!(JSON.stringify(fields)===JSON.stringify(['code','message'])
          ||JSON.stringify(fields)===JSON.stringify(['code','data','message']))
        ||!Number.isSafeInteger(value.error.code)||typeof value.error.message!=='string'
        ||value.error.message.length===0||Buffer.byteLength(value.error.message,'utf8')>4096) {
      throw new Error('invalid upstream JSON-RPC response');
    }
  }
  return value;
}
