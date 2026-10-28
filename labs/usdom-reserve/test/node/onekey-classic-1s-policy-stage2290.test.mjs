import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const readJson=path=>JSON.parse(readFileSync(new URL(path,import.meta.url),'utf8'));

test('production hardware policy is fail-closed for OneKey Classic 1S',()=>{
 const policy=readJson('../../config/onekey-classic-1s-policy.unconfigured.json');
 assert.equal(policy.vendor,'OneKey');
 assert.equal(policy.model,'Classic 1S');
 assert.equal(policy.transport,'BLE');
 assert.equal(policy.bleTransport,'official-sdk-required');
 assert.equal(policy.desktopElectronBleHandoff,'laboratory-only-disabled-in-production');
 assert.equal(policy.usbFallback,false);
 assert.equal(policy.ethereumDerivationPath,"m/44'/60'/0'/0/0");
 assert.equal(policy.addressVerification,'on-device-required');
 for(const key of ['sdkVersion','sdkArtifactSha256','firmwareVersion','firmwareFingerprint',
  'transportVersion','transportArtifactSha256']) assert.equal(policy[key],null,key);
 for(const key of ['eip1559SigningVerified','eip712SigningVerified','userRejectionVerified',
  'userCancellationVerified','disconnectVerified','reconnectVerified','blePairingVerified',
  'blePermissionsVerified','bleDeviceIdentityVerified','bleReconnectIdentityVerified']) {
  assert.equal(policy[key],false,key);
 }
 assert.equal(policy.ledgerProductionCompatibility,false);

 const requirements=readJson('../../config/production-requirements.json');
 for(const key of [
  'production_onekey_classic_1s_model_pinned',
  'production_onekey_official_ble_transport_pinned',
  'production_onekey_ble_pairing_and_permissions_verified',
  'production_onekey_ble_device_identity_and_reconnection_verified',
  'production_onekey_usb_fallback_disabled',
  'production_onekey_ethereum_derivation_path_explicit',
  'production_onekey_address_verified_on_device',
  'production_onekey_sdk_firmware_transport_versions_pinned',
  'production_onekey_eip1559_and_eip712_signing_verified',
  'production_onekey_reject_cancel_disconnect_reconnect_verified',
  'production_ledger_compatibility_disabled',
 ]) assert.equal(requirements[key],false,key);
 for(const key of [
  'production_recoverable_safe_control_signing_inputs_rechecked_per_onekey_action',
  'production_release_authorization_signing_inputs_rechecked_per_onekey_action',
  'production_safe_recovery_executor_external_gas_only_relayer_verified',
 ]) assert.equal(requirements[key],true,key);
 assert.equal(Object.hasOwn(requirements,'production_onekey_usb_transport_pinned'),false);
 for(const old of [
  'production_recoverable_safe_control_signing_inputs_rechecked_per_ledger_action',
  'production_release_authorization_signing_inputs_rechecked_per_ledger_action',
  'production_safe_recovery_executor_relayer_derived_from_ledger',
  'production_safe_recovery_executor_relayer_derived_from_onekey',
 ]) assert.equal(Object.hasOwn(requirements,old),false,old);
});
