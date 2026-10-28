const canonicalPath=/^scripts\/[a-z0-9][a-z0-9.-]*\.(?:sh|mjs)$/;
const ledgerOption=/(?:^|[^A-Za-z0-9_-])--ledger(?![A-Za-z0-9_-])/u;
const legacyProductionReference=/(?:onekey-electron-ble|electron\/onekey-ble|onekey-bluetooth-factory|desktop-web-ble|sign-onekey-mainnet-(?:transaction|typed-data))/u;

export function auditOneKeyProductionBoundary({inventory,readSource,allScriptPaths}) {
 if(!inventory||inventory.schema!==1||!Array.isArray(inventory.scripts)
     ||inventory.scripts.length===0) throw new Error('invalid OneKey production script inventory');
 const scripts=[...inventory.scripts];
 if(new Set(scripts).size!==scripts.length||scripts.some(path=>!canonicalPath.test(path))) {
  throw new Error('OneKey production script inventory paths are invalid or duplicated');
 }
 const discovered=allScriptPaths===undefined?scripts:[...allScriptPaths];
 if(new Set(discovered).size!==discovered.length
     ||discovered.some(path=>!canonicalPath.test(path))) {
  throw new Error('OneKey production script discovery paths are invalid or duplicated');
 }
 const inventorySet=new Set(scripts);
 const violations=[];
 for(const path of discovered) {
  const source=readSource(path);
  if(typeof source!=='string') throw new Error(`missing production script: ${path}`);
  source.split(/\r?\n/u).forEach((line,index)=>{
   if(ledgerOption.test(line)) {
    violations.push({path,line:index+1,
     reason:inventorySet.has(path)?'ledger-option':'uninventoried-ledger-option'});
   }
   if(inventorySet.has(path)&&legacyProductionReference.test(line)) {
    violations.push({path,line:index+1,reason:'legacy-electron-ble-reference'});
   }
  });
 }
 return {ok:violations.length===0,checked:scripts.length,
  discovered:discovered.length,violations};
}
