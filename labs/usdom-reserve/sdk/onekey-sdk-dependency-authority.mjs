const packageName=/^(?:@[a-z0-9-]+\/[a-z0-9-]+|[a-z0-9-]+)$/u;
const zeroAudit={info:0,low:0,moderate:0,high:0,critical:0,total:0};

const sameRecord=(actual,expected)=>Object.keys(expected).length===Object.keys(actual??{}).length
 &&Object.entries(expected).every(([key,value])=>actual[key]===value);

export function auditOneKeySdkDependencyAuthority({authority,packageJson,packageLock,
 auditReport}={}) {
 const violations=[];
 const fail=(reason,detail)=>violations.push({reason,detail});
 if(!authority||authority.schema!==1) fail('authority-schema','expected schema 1');
 if(authority?.status!=='offline-ble-renderer-and-minimal-noble-host-approved-runtime-unconfigured') fail('authority-status',authority?.status);
 if(authority?.hardwareSigningApproved!==false) fail('hardware-gate','must remain false');
 if(authority?.officialPackage!=='@onekeyfe/hd-common-connect-sdk'
   ||authority?.officialVersion!=='1.2.7') fail('official-sdk-pin','expected 1.2.7');
 if(!/^[0-9a-f]{40}$/u.test(authority?.publishedGitHead??'')) {
  fail('published-git-head','invalid gitHead');
 }
 if(authority?.runtimeTransport!=='desktop-web-ble'
   ||JSON.stringify(authority?.allowedRuntimeTransports)!=='["desktop-web-ble"]') {
  fail('runtime-transport','only desktop-web-ble is allowed');
 }
 for(const prohibited of ['emulator','http','node-usb','webusb','desktop-webusb','react-native','lowlevel']) {
  if(!authority?.prohibitedRuntimeTransports?.includes(prohibited)) {
   fail('prohibited-transport',prohibited);
  }
 }
 const identity=authority?.deviceIdentity;
 if(identity?.persistentBinding!=='deviceId'||identity?.ephemeralLocator!=='connectId'
   ||identity?.requireSingleLiveBleDevice!==true||identity?.requireProtocol!=='V1'
   ||identity?.requireModel!=='Classic 1S'||!Array.isArray(identity?.firmwareAllowlist)
   ||identity.firmwareAllowlist.length!==0||identity?.electronHostApproved!==true) fail('device-identity-gate','invalid fail-closed identity policy');
 if(!sameRecord(packageJson?.overrides,authority?.overrides??{})) {
  fail('override-pins','package.json overrides differ from authority');
 }
 if(!sameRecord(authority?.directDependencies??{},Object.fromEntries(
  Object.keys(authority?.directDependencies??{}).map(name=>[name,packageJson?.dependencies?.[name]])))) {
  fail('direct-dependency-pins','package.json direct dependencies differ from authority');
 }
 for(const prohibited of authority?.transitiveInstalledButRuntimeProhibited??[]) {
  if(packageJson?.dependencies?.[prohibited]!==undefined) fail('prohibited-direct-dependency',prohibited);
  if(!packageLock?.packages?.[`node_modules/${prohibited}`]) fail('missing-declared-transitive',prohibited);
 }
 const root=packageLock?.packages?.[''];
 for(const [name,version] of Object.entries(authority?.directDependencies??{})) {
  if(root?.dependencies?.[name]!==version) fail('lock-root-pin',`${name}@${root?.dependencies?.[name]}`);
 }
 const seen=new Set();
 for(const expected of authority?.packages??[]) {
  if(!packageName.test(expected?.name??'')||seen.has(expected.name)) {
   fail('authority-package-name',expected?.name); continue;
  }
  seen.add(expected.name);
  const actual=packageLock?.packages?.[`node_modules/${expected.name}`];
  for(const field of ['version','integrity','license']) {
   if(actual?.[field]!==expected[field]) {
    fail('lock-package-authority',`${expected.name}.${field}`);
   }
  }
 }
 for(const [name,version] of Object.entries(authority?.overrides??{})) {
  if(packageLock?.packages?.[`node_modules/${name}`]?.version!==version) {
   fail('resolved-override',`${name}@${packageLock?.packages?.[`node_modules/${name}`]?.version}`);
  }
 }
 const audit=auditReport?.metadata?.vulnerabilities??authority?.audit?.vulnerabilities;
 if(!sameRecord(audit,zeroAudit)) fail('dependency-audit','audit is not zero');
 if(authority?.offlineCompatibility?.electronBleTransportImportVerified!==true
   ||authority?.offlineCompatibility?.nativeBleHardwareExercised!==false) {
  fail('hardware-compatibility-gate','must remain false until physical validation');
 }
 const host=authority?.electronBleHost;
 const profile=host?.securityProfile;
 if(host?.officialInterface!=='window.desktopApi.nobleBle'
   ||host?.officialMainInitializer!=='initNobleBleSupport'
   ||host?.hostPackageAccepted!==false||host?.minimalNobleAdapterAccepted!==true
   ||host?.minimalNoblePackage!=='@stoprocent/noble'||host?.minimalNobleVersion!=='2.3.16'
   ||host?.thirdPartyHwkAlphaAccepted!==false
   ||profile?.nodeIntegration!==false||profile?.contextIsolation!==true
   ||profile?.sandbox!==true||profile?.remoteContent!==false
   ||profile?.rpcOrBroadcast!==false||profile?.privateFileMode!=='0600'
   ||profile?.privateDirectoryMode!=='0700') fail('electron-ble-host-gate','invalid BLE host authority');
 return {ok:violations.length===0,violations,packages:seen.size};
}
