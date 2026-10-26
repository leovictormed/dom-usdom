const depositIdentity=new Set(['depositid','funder','receivingcommitment','recipientaddress','salt']);
const redemptionIdentity=new Set(['burnid','requestid','recipient']);
const secretMaterial=new Set(['witness','privatewitness','rho','secretnullifier','nullifiersecret',
  'memoplaintext','plaintextmemo','raw','rawtransaction','signedtransaction']);

export function auditPilotPublicArtifact(value) {
  let hasDeposit=false,hasRedemption=false;
  const visit=current=>{
    if(Array.isArray(current)) { for(const item of current) visit(item); return; }
    if(!current||typeof current!=='object') {
      if(typeof current==='string'&&/^0x0[12][0-9a-fA-F]{180,}$/.test(current)) {
        throw new Error('public pilot artifact contains a raw signed transaction');
      }
      return;
    }
    for(const [key,item] of Object.entries(current)) {
      const normalized=key.replaceAll(/[_-]/g,'').toLowerCase();
      if(secretMaterial.has(normalized)||normalized.includes('memoplaintext')
          ||normalized.includes('privatewitness')||normalized.includes('secretnullifier')) {
        throw new Error(`public pilot artifact contains private material: ${key}`);
      }
      if(depositIdentity.has(normalized)) hasDeposit=true;
      if(redemptionIdentity.has(normalized)) hasRedemption=true;
      visit(item);
    }
  };
  visit(value);
  if(hasDeposit&&hasRedemption) throw new Error('public pilot artifact links deposit and redemption identities');
  return {containsDepositIdentity:hasDeposit,containsRedemptionIdentity:hasRedemption};
}
