const whitespace=code=>code===0x20||code===0x09||code===0x0a||code===0x0d;
const hasUnpairedSurrogate=value=>{
 for(let index=0;index<value.length;index++) {
  const code=value.charCodeAt(index);
  if(code>=0xd800&&code<=0xdbff) {
   const low=value.charCodeAt(index+1);
   if(!(low>=0xdc00&&low<=0xdfff)) return true;
   index++;
  } else if(code>=0xdc00&&code<=0xdfff) return true;
 }
 return false;
};

/**
 * Parse security-sensitive JSON while rejecting duplicate object keys.
 *
 * JSON.parse accepts the last occurrence of a duplicate key. That behavior is
 * unsafe for release manifests because reviewers and machines can interpret
 * the same bytes differently. Keys are compared after escape decoding, so
 * `"ready"` and `"\u0072eady"` are duplicates.
 */
export function parseStrictJson(source,{label='JSON',maxBytes=64*1024*1024,maxDepth=128,
 maxNodes=1_000_000,maxStringBytes=maxBytes,maxObjectEntries=100_000,
 maxArrayEntries=100_000}={}) {
 if(typeof source!=='string') throw new TypeError(`${label}: input must be text`);
 for(const [name,value] of Object.entries({maxBytes,maxDepth,maxNodes,maxStringBytes,
  maxObjectEntries,maxArrayEntries})) {
  if(!Number.isSafeInteger(value)||value<1) throw new RangeError(`${label}: ${name} is invalid`);
 }
 if(Buffer.byteLength(source,'utf8')>maxBytes) throw new SyntaxError(`${label}: input exceeds ${maxBytes} bytes`);
 let offset=0,nodes=0;
 const fail=message=>{throw new SyntaxError(`${label}: ${message} at character ${offset}`);};
 const skip=()=>{while(offset<source.length&&whitespace(source.charCodeAt(offset))) offset++;};
 const string=()=>{
  if(source[offset]!=='"') fail('expected string');
  const start=offset++;
  while(offset<source.length) {
   const code=source.charCodeAt(offset++);
   if(code===0x22) {
    let result;
    try { result=JSON.parse(source.slice(start,offset)); }
    catch { fail('invalid string escape'); }
    // Isolated UTF-16 surrogate escapes become U+FFFD when encoded as UTF-8.
    // Reject them before hashing/re-encoding to keep one string -> one byte form.
    if(hasUnpairedSurrogate(result)) fail('unpaired Unicode surrogate');
    if(Buffer.byteLength(result,'utf8')>maxStringBytes) fail(`string exceeds ${maxStringBytes} bytes`);
    return result;
   }
   if(code<0x20) fail('unescaped control character in string');
   if(code===0x5c) {
    if(offset>=source.length) fail('truncated string escape');
    offset++;
   }
  }
  fail('unterminated string');
 };
 const literal=(text,value)=>{
  if(source.slice(offset,offset+text.length)!==text) fail('invalid literal');
  offset+=text.length;
  return value;
 };
 const number=()=>{
  const match=source.slice(offset).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
  if(!match) fail('invalid number');
  offset+=match[0].length;
  const value=Number(match[0]);
  if(!Number.isFinite(value)) fail('non-finite number');
  if(!Number.isSafeInteger(value)&&!/[.eE]/.test(match[0])) fail('integer is not canonically representable');
  // JSON.parse silently rounds decimal/exponent spellings such as
  // 0.10000000000000001.  A security boundary must not let two distinct
  // numeric tokens collapse to the same IEEE-754 value.  Requiring the
  // ECMAScript shortest round-trip spelling also excludes -0, redundant
  // fractions and alternate exponent forms before callers hash/re-encode.
  if(JSON.stringify(value)!==match[0]) fail('number is not canonically representable');
  return value;
 };
 const value=depth=>{
  if(depth>maxDepth) fail(`nesting exceeds ${maxDepth}`);
  nodes++;
  if(nodes>maxNodes) fail(`node count exceeds ${maxNodes}`);
  skip();
  const next=source[offset];
  if(next==='"') return string();
  if(next==='t') return literal('true',true);
  if(next==='f') return literal('false',false);
  if(next==='n') return literal('null',null);
  if(next==='-'||(next>='0'&&next<='9')) return number();
  if(next==='[') {
   offset++; skip();
   const result=[];
   if(source[offset]===']') {offset++; return result;}
   while(true) {
    if(result.length>=maxArrayEntries) fail(`array entries exceed ${maxArrayEntries}`);
    result.push(value(depth+1)); skip();
    if(source[offset]===']') {offset++; return result;}
    if(source[offset]!==',') fail("expected ',' or ']'");
    offset++; skip();
   }
  }
  if(next==='{') {
   offset++; skip();
   const result=Object.create(null);
   const keys=new Set();
   if(source[offset]==='}') {offset++; return result;}
   while(true) {
    const key=string();
    if(keys.size>=maxObjectEntries) fail(`object entries exceed ${maxObjectEntries}`);
    if(keys.has(key)) fail(`duplicate object key ${JSON.stringify(key)}`);
    keys.add(key); skip();
    if(source[offset]!==':') fail("expected ':'");
    offset++;
    result[key]=value(depth+1); skip();
    if(source[offset]==='}') {offset++; return result;}
    if(source[offset]!==',') fail("expected ',' or '}'");
    offset++; skip();
   }
  }
  fail('expected JSON value');
 };
 const result=value(0);
 skip();
 if(offset!==source.length) fail('trailing content');
 return result;
}

/** Decode untrusted bytes as canonical UTF-8 before strict JSON parsing. */
export function parseStrictJsonBytes(bytes,options={}) {
 const label=options.label??'JSON';
 let source;
 try { source=new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
 catch { throw new SyntaxError(`${label}: input contains invalid UTF-8`); }
 return parseStrictJson(source,options);
}
