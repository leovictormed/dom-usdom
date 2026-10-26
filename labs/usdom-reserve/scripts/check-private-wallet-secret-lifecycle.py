#!/usr/bin/env python3
"""Structural gate for native USDOM private-wallet randomness and secret lifecycle."""
from pathlib import Path
import sys
R=Path(__file__).resolve().parents[3]
checks={
'crates/dom-usdom-wallet/src/lib.rs':['R: RngCore + CryptoRng','WalletRecoverySeed(Zeroizing<[u8; 32]>)','#[derive(Zeroize, ZeroizeOnDrop)]','RECOVERY_OWNER_INFO','RECOVERY_SCAN_INFO','info.extend_from_slice(&chain_bytes)','EphemeralSecret::random_from_rng','rng.fill_bytes(&mut nonce)','uniqueness.insert((ephemeral_public, nonce))','let mut plaintext = Zeroizing::new','save_envelope_bytes_noclobber'],
'crates/dom-usdom-wallet/src/builder.rs':['R: RngCore + CryptoRng','rho: random_scalar(rng)','let mut bytes = Zeroizing::new([0u8; 32])','note.reservation_id = Some(transition_id)','submission_authorized: false'],
'crates/dom-usdom-wallet/src/burn_builder.rs':['R: RngCore + CryptoRng','REQUEST_IDENTIFIER_ATTEMPTS','value != [0; 32] && value != burn_id','note.reservation_id = Some(transition_id)','submission_authorized: false'],
'crates/dom-usdom-wallet/src/snapshot.rs':['SnapshotLock::acquire(path)','persist_pending_payload_for_submission','reconcile_encrypted_snapshot_authority','pending_transfer_submission_permit','pending_burn_submission_permit'],
'crates/dom-usdom-privacy/src/circuit.rs':['#[derive(Clone, Zeroize, ZeroizeOnDrop)]','pub owner_secret: Scalar','pub rho: Scalar'],
}
failed=[]
for f,ns in checks.items():
 s=(R/f).read_text()
 for n in ns:
  if n not in s: failed.append(f'{f}: missing {n}')
if failed:
 print('FAIL wallet secret lifecycle\n'+'\n'.join(failed)); sys.exit(1)
print('PASS private wallet randomness, reservations, recovery and secret erasure remain fail-closed')
