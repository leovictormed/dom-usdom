const FACTS=['classic1sPolicyPinned','iosWalletConnectAuthorityPinned','iosWalletConnectClientPinned','iosWalletConnectSessionRuntimeApproved','iosWalletConnectNetworkApproved','iosHardwareAccountObserved','physicalIdentityAndReconnectObserved','physicalFailureExercisesObserved','physicalExactEip712Observed','singleOperatorRatificationBound','usbFallbackDisabled','ledgerCompatibilityDisabled'];
const exact=(v,k,l)=>{if(v===null||typeof v!=='object'||Array.isArray(v)||JSON.stringify(Object.keys(v).sort())!==JSON.stringify([...k].sort()))throw new Error(`${l} schema invalid`);};
export function evaluateOneKeyProductionReadinessDag(authority) {
 exact(authority,['schema','status','productionRoute','linuxBleProductionApplicable','facts'],'OneKey DAG authority');exact(authority.facts,FACTS,'OneKey DAG facts');
 if(authority.schema!=='usdom-onekey-production-readiness-dag-v2'||authority.productionRoute!=='onekey-ios-walletconnect-eip712-only'||authority.linuxBleProductionApplicable!==false
   ||Object.values(authority.facts).some(x=>typeof x!=='boolean'))throw new Error('OneKey production DAG authority is invalid');
 const f=authority.facts;
 const stages={policy:f.classic1sPolicyPinned&&f.usbFallbackDisabled&&f.ledgerCompatibilityDisabled};
 stages.mobileTransport=stages.policy&&f.iosWalletConnectAuthorityPinned&&f.iosWalletConnectClientPinned&&f.iosWalletConnectSessionRuntimeApproved&&f.iosWalletConnectNetworkApproved;
 stages.physicalCeremony=stages.mobileTransport&&f.iosHardwareAccountObserved&&f.physicalIdentityAndReconnectObserved&&f.physicalFailureExercisesObserved;
 stages.physicalSigning=stages.physicalCeremony&&f.physicalExactEip712Observed;
 stages.operatorRatification=stages.physicalSigning&&f.singleOperatorRatificationBound;
 const hardwareSigningApproved=stages.operatorRatification;
 return Object.freeze({schema:'usdom-onekey-production-readiness-result-v2',productionRoute:authority.productionRoute,stages:Object.freeze(stages),hardwareSigningApproved,
  readinessGates:Object.freeze({production_onekey_ios_walletconnect_authority_pinned:stages.mobileTransport,
   production_onekey_ios_walletconnect_session_runtime_pinned:stages.mobileTransport,
   production_onekey_ios_exact_eip712_signing_verified:stages.physicalSigning,
   production_onekey_mobile_physical_ceremony_ratified:stages.operatorRatification,
   production_onekey_hardware_signing_approved:hardwareSigningApproved})});
}
export const ONEKEY_PRODUCTION_DAG_FACTS=Object.freeze([...FACTS]);
