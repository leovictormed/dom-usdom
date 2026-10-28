const depositIdentity=new Set(['depositid','funder','receivingcommitment','recipientaddress','salt']);
const redemptionIdentity=new Set(['burnid','requestid','recipient','payoutaddress']);
const genericIdentity=new Set(['id','address','commitment','transactionhash','txhash']);
const depositContext=new Set(['deposit','issuance','funder','receiving','mint']);
const redemptionContext=new Set(['burn','redemption','withdrawal','payout','redeem']);
const secretMaterial=new Set(['witness','privatewitness','rho','secretnullifier','nullifiersecret',
  'memoplaintext','plaintextmemo','raw','rawtransaction','signedtransaction','privatekey',
  'secretkey','seed','mnemonic','passphrase','password','ownersecret','scansecret','noteopening']);

const normalizedKey=key=>key.replaceAll(/[_-]/g,'').toLowerCase();
const contextIncludes=(path,contexts)=>path.some(part=>{
  for(const context of contexts) if(part.includes(context)) return true;
  return false;
});
const scalarIdentity=value=>typeof value==='string'&&value.length<=512?value.toLowerCase():null;

function inspectPilotPublicArtifact(value) {
  let hasDeposit=false,hasRedemption=false;
  const depositValues=new Set(),redemptionValues=new Set();
  const visit=(current,path=[])=>{
    if(Array.isArray(current)) { for(const item of current) visit(item,path); return; }
    if(!current||typeof current!=='object') {
      if(typeof current==='string'&&/^0x0[12][0-9a-fA-F]{180,}$/.test(current)) {
        throw new Error('public pilot artifact contains a raw signed transaction');
      }
      return;
    }
    for(const [key,item] of Object.entries(current)) {
      const normalized=normalizedKey(key);
      const itemPath=[...path,normalized];
      if(secretMaterial.has(normalized)||normalized.includes('memoplaintext')
          ||normalized.includes('privatewitness')||normalized.includes('secretnullifier')
          ||normalized.endsWith('privatekey')||normalized.endsWith('ownersecret')
          ||normalized.endsWith('scansecret')) {
        throw new Error(`public pilot artifact contains private material: ${key}`);
      }
      const deposit=depositIdentity.has(normalized)
        ||(genericIdentity.has(normalized)&&contextIncludes(itemPath,depositContext));
      const redemption=redemptionIdentity.has(normalized)
        ||(genericIdentity.has(normalized)&&contextIncludes(itemPath,redemptionContext));
      if(deposit) { hasDeposit=true; const scalar=scalarIdentity(item); if(scalar!==null) depositValues.add(scalar); }
      if(redemption) { hasRedemption=true; const scalar=scalarIdentity(item); if(scalar!==null) redemptionValues.add(scalar); }
      visit(item,itemPath);
    }
  };
  visit(value);
  if(hasDeposit&&hasRedemption) throw new Error('public pilot artifact links deposit and redemption identities');
  return {hasDeposit,hasRedemption,depositValues,redemptionValues};
}

export function auditPilotPublicArtifact(value) {
  const inspected=inspectPilotPublicArtifact(value);
  return {containsDepositIdentity:inspected.hasDeposit,
    containsRedemptionIdentity:inspected.hasRedemption};
}

/** Audit a publication as a set, including path names and cross-file reuse. */
export function auditPilotPublicArtifactSet(entries) {
  if(!Array.isArray(entries)||entries.length===0) throw new Error('public artifact set is empty');
  const deposits=new Set(),redemptions=new Set();
  for(const entry of entries) {
    if(!entry||typeof entry.label!=='string'||entry.label.length===0||entry.label.length>4096) {
      throw new Error('public artifact label is invalid');
    }
    const label=entry.label.toLowerCase();
    const labelHasDeposit=/(^|[/_.-])(deposit|issuance|mint)([/_.-]|$)/.test(label);
    const labelHasRedemption=/(^|[/_.-])(burn|redemption|withdrawal|payout)([/_.-]|$)/.test(label);
    if(labelHasDeposit&&labelHasRedemption) {
      throw new Error('public artifact filename links deposit and redemption phases');
    }
    const inspected=inspectPilotPublicArtifact(entry.value);
    for(const identity of inspected.depositValues) deposits.add(identity);
    for(const identity of inspected.redemptionValues) redemptions.add(identity);
  }
  for(const identity of deposits) {
    if(redemptions.has(identity)) throw new Error('public artifact set reuses an identity across phases');
  }
  return {artifactCount:entries.length};
}
