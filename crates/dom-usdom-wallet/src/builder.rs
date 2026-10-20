//! Deterministic note selection and complete proof-backed private transfers.

use dom_core::Hash256;
use dom_usdom_privacy::{
    circuit::{InputWitness, OutputWitness, SpendCircuit, SpendStatement},
    memo_scalar, Scalar,
};
use dom_usdom_prover::{ProverError, SpendProver};
use dom_usdom_state::{
    encode_private_transfer_payload, private_transfer_payload_id, NoteAnchor, UsdomStateError,
};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{
    encrypt_outputs, MemoOutput, RecipientAddress, WalletError, WalletSecrets, WalletState,
};

pub(super) struct PendingPrivateTransfer {
    pub(super) anchor: NoteAnchor,
    pub(super) created_at_tip: Hash256,
    pub(super) created_at_height: u64,
    pub(super) selected_commitments: Vec<[u8; 32]>,
    pub(super) nullifiers: Vec<[u8; 32]>,
    pub(super) payload: Vec<u8>,
    pub(super) submission_authorized: bool,
}

/// Public state of one persistently reserved private transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPrivateTransferSummary {
    /// Identifier of the exact randomized proof payload.
    pub transition_id: Hash256,
    /// Tip at which its membership witnesses were constructed.
    pub created_at_tip: Hash256,
    /// Height of that tip.
    pub created_at_height: u64,
    /// Exact proof anchor.
    pub anchor: NoteAnchor,
    /// Reserved owned note commitments.
    pub selected_commitments: Vec<[u8; 32]>,
    /// Public nullifiers used to detect canonical confirmation.
    pub nullifiers: Vec<[u8; 32]>,
    /// Number of exact nullifiers currently present in canonical wallet state.
    pub canonical_nullifier_count: usize,
    /// Whether every input nullifier is currently present in canonical state.
    /// This does not by itself prove inclusion of this exact randomized payload.
    pub all_inputs_canonically_spent: bool,
    /// Whether this exact randomized payload identifier is canonical.
    pub exact_payload_canonical: bool,
    /// Whether a rollback-resistant snapshot authority committed this intent
    /// before network submission became possible.
    pub submission_authorized: bool,
}

/// Failure while selecting notes or constructing a proof-backed transfer.
#[derive(Debug, Error)]
pub enum PrivateTransferBuildError {
    /// Recipient, amount, note, witness, or output construction was invalid.
    #[error("invalid USDOM private transfer request: {0}")]
    Wallet(#[from] WalletError),
    /// No one- or two-note selection can cover the requested amount safely.
    #[error("insufficient USDOM value spendable within the two-input circuit")]
    InsufficientSpendableNotes,
    /// Selected input addition or change cannot fit the frozen u64 relation.
    #[error("USDOM private transfer amount arithmetic overflow")]
    AmountOverflow,
    /// Offline proof construction or mandatory self-verification failed.
    #[error("USDOM private transfer proof failed: {0}")]
    Prover(#[from] ProverError),
    /// Canonical state payload encoding failed.
    #[error("USDOM private transfer payload encoding failed: {0}")]
    Payload(#[from] UsdomStateError),
    /// A selected note is already reserved or the identifier already exists.
    #[error("USDOM private transfer input is already reserved")]
    AlreadyReserved,
    /// No pending transfer has the requested identifier.
    #[error("unknown USDOM pending private transfer")]
    UnknownPendingTransfer,
    /// Cancellation was requested after a selected nullifier became canonical.
    #[error("cannot cancel a canonically observed USDOM private transfer")]
    PendingTransferObserved,
    /// Cancellation was requested after durable network submission authority.
    #[error("cannot cancel a USDOM private transfer authorized for submission")]
    PendingTransferAuthorized,
}

/// Complete canonical private-transfer bytes plus public tracking metadata.
pub struct BuiltPrivateTransfer {
    payload: Vec<u8>,
    transition_id: Hash256,
    anchor: NoteAnchor,
    selected_commitments: Vec<[u8; 32]>,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    amount: u64,
    change: u64,
}

impl BuiltPrivateTransfer {
    /// Canonical payload accepted by native private-transfer verification.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Domain-separated identifier of the exact randomized proof payload.
    pub fn transition_id(&self) -> Hash256 {
        self.transition_id
    }
    /// Exact note-tree anchor under which the proof was constructed.
    pub fn anchor(&self) -> NoteAnchor {
        self.anchor
    }
    /// Owned note commitments selected as hidden inputs.
    pub fn selected_commitments(&self) -> &[[u8; 32]] {
        &self.selected_commitments
    }
    /// Canonically sorted public nullifiers.
    pub fn nullifiers(&self) -> &[[u8; 32]] {
        &self.nullifiers
    }
    /// New public note commitments in memo and circuit order.
    pub fn output_commitments(&self) -> &[[u8; 32]] {
        &self.output_commitments
    }
    /// Recipient amount in six-decimal base units.
    pub fn amount(&self) -> u64 {
        self.amount
    }
    /// Private change returned to this wallet.
    pub fn change(&self) -> u64 {
        self.change
    }
}

struct PreparedPrivateTransfer {
    circuit: SpendCircuit,
    anchor: NoteAnchor,
    selected_commitments: Vec<[u8; 32]>,
    nullifiers: Vec<[u8; 32]>,
    output_commitments: Vec<[u8; 32]>,
    memo: Vec<u8>,
    amount: u64,
    change: u64,
}

impl WalletState {
    /// Select at most two unspent notes, create recipient and optional change
    /// outputs, prove the frozen relation, self-verify it, and encode the exact
    /// native payload. Selected inputs are atomically reserved after proof
    /// construction succeeds; submission remains an explicit caller action.
    pub fn build_private_transfer<R: RngCore + CryptoRng>(
        &mut self,
        wallet: &WalletSecrets,
        prover: &SpendProver,
        recipient: RecipientAddress,
        amount: u64,
        rng: &mut R,
    ) -> Result<BuiltPrivateTransfer, PrivateTransferBuildError> {
        let prepared = self.prepare_private_transfer(wallet, recipient, amount, rng)?;
        let proof = prover.prove(prepared.circuit, rng)?;
        let payload = encode_private_transfer_payload(
            prepared.anchor,
            &prepared.nullifiers,
            &prepared.output_commitments,
            &prepared.memo,
            &proof,
        )?;
        let transition_id = private_transfer_payload_id(&payload);
        if self
            .pending_transfers
            .contains_key(transition_id.as_bytes())
            || prepared.selected_commitments.iter().any(|commitment| {
                self.notes
                    .get(commitment)
                    .is_none_or(|note| note.spent || note.reservation_id.is_some())
            })
        {
            return Err(PrivateTransferBuildError::AlreadyReserved);
        }
        for commitment in &prepared.selected_commitments {
            let Some(note) = self.notes.get_mut(commitment) else {
                return Err(PrivateTransferBuildError::AlreadyReserved);
            };
            note.reservation_id = Some(transition_id);
        }
        self.pending_transfers.insert(
            *transition_id.as_bytes(),
            PendingPrivateTransfer {
                anchor: prepared.anchor,
                created_at_tip: self.tip_identifier,
                created_at_height: self.tip_height,
                selected_commitments: prepared.selected_commitments.clone(),
                nullifiers: prepared.nullifiers.clone(),
                payload: payload.clone(),
                submission_authorized: false,
            },
        );
        Ok(BuiltPrivateTransfer {
            payload,
            transition_id,
            anchor: prepared.anchor,
            selected_commitments: prepared.selected_commitments,
            nullifiers: prepared.nullifiers,
            output_commitments: prepared.output_commitments,
            amount: prepared.amount,
            change: prepared.change,
        })
    }

    /// Summaries of every pending reservation in identifier order.
    pub fn pending_private_transfers(&self) -> Vec<PendingPrivateTransferSummary> {
        self.pending_transfers
            .iter()
            .map(|(transition_id, pending)| {
                let canonical_nullifier_count = pending
                    .nullifiers
                    .iter()
                    .filter(|value| self.seen_nullifiers.contains(*value))
                    .count();
                PendingPrivateTransferSummary {
                    transition_id: Hash256::from_bytes(*transition_id),
                    created_at_tip: pending.created_at_tip,
                    created_at_height: pending.created_at_height,
                    anchor: pending.anchor,
                    selected_commitments: pending.selected_commitments.clone(),
                    nullifiers: pending.nullifiers.clone(),
                    canonical_nullifier_count,
                    all_inputs_canonically_spent: canonical_nullifier_count
                        == pending.nullifiers.len(),
                    exact_payload_canonical: self.seen_private_payloads.contains(transition_id),
                    submission_authorized: pending.submission_authorized,
                }
            })
            .collect()
    }

    /// Exact payload retained for authenticated resubmission.
    pub fn pending_private_transfer_payload(&self, transition_id: Hash256) -> Option<&[u8]> {
        self.pending_transfers
            .get(transition_id.as_bytes())
            .map(|pending| pending.payload.as_slice())
    }

    #[cfg(feature = "rpc-client")]
    pub(crate) fn authorized_private_transfer_payload(
        &self,
        transition_id: Hash256,
    ) -> Option<&[u8]> {
        self.pending_transfers
            .get(transition_id.as_bytes())
            .filter(|pending| pending.submission_authorized)
            .map(|pending| pending.payload.as_slice())
    }

    /// Cancel a transfer only while none of its nullifiers is canonical.
    pub fn cancel_pending_private_transfer(
        &mut self,
        transition_id: Hash256,
    ) -> Result<(), PrivateTransferBuildError> {
        let pending = self
            .pending_transfers
            .get(transition_id.as_bytes())
            .ok_or(PrivateTransferBuildError::UnknownPendingTransfer)?;
        if pending
            .nullifiers
            .iter()
            .any(|value| self.seen_nullifiers.contains(value))
        {
            return Err(PrivateTransferBuildError::PendingTransferObserved);
        }
        if pending.submission_authorized {
            return Err(PrivateTransferBuildError::PendingTransferAuthorized);
        }
        let selected = pending.selected_commitments.clone();
        self.pending_transfers.remove(transition_id.as_bytes());
        for commitment in selected {
            if let Some(note) = self.notes.get_mut(&commitment) {
                if note.reservation_id == Some(transition_id) {
                    note.reservation_id = None;
                }
            }
        }
        Ok(())
    }

    fn prepare_private_transfer<R: RngCore + CryptoRng>(
        &self,
        wallet: &WalletSecrets,
        recipient: RecipientAddress,
        amount: u64,
        rng: &mut R,
    ) -> Result<PreparedPrivateTransfer, PrivateTransferBuildError> {
        if amount == 0 || wallet.chain != self.chain || recipient.chain() != self.chain {
            return Err(WalletError::InvalidIdentity.into());
        }
        recipient.validate()?;
        let selected = self.select_transfer_notes(amount)?;
        let total = selected.iter().try_fold(0u64, |sum, commitment| {
            let value = self
                .notes
                .get(commitment)
                .ok_or(PrivateTransferBuildError::InsufficientSpendableNotes)?
                .received
                .opening
                .value;
            sum.checked_add(value)
                .ok_or(PrivateTransferBuildError::AmountOverflow)
        })?;
        let change = total
            .checked_sub(amount)
            .ok_or(PrivateTransferBuildError::InsufficientSpendableNotes)?;

        let mut inputs = Vec::with_capacity(selected.len());
        for commitment in &selected {
            let scalar = Scalar::from_bytes(*commitment).map_err(WalletError::from)?;
            let witness = self.spend_witness(wallet, scalar)?;
            let note = self
                .notes
                .get(commitment)
                .ok_or(PrivateTransferBuildError::InsufficientSpendableNotes)?;
            let nullifier = wallet.nullifier_for(&note.received.opening)?;
            inputs.push((nullifier, witness, *commitment));
        }
        inputs.sort_by_key(|(nullifier, _, _)| nullifier.to_bytes());
        let selected_commitments = inputs
            .iter()
            .map(|(_, _, value)| *value)
            .collect::<Vec<_>>();
        let nullifiers = inputs
            .iter()
            .map(|(value, _, _)| value.to_bytes())
            .collect::<Vec<_>>();

        let mut memo_outputs = vec![MemoOutput {
            recipient,
            value: amount,
            rho: random_scalar(rng),
        }];
        if change != 0 {
            memo_outputs.push(MemoOutput {
                recipient: wallet.address()?,
                value: change,
                rho: random_scalar(rng),
            });
            if rng.next_u32() & 1 == 1 {
                memo_outputs.swap(0, 1);
            }
        }
        let output_witnesses = memo_outputs
            .iter()
            .map(|output| OutputWitness {
                enabled: true,
                value: output.value,
                owner: output.recipient.owner(),
                rho: output.rho,
            })
            .collect::<Vec<_>>();
        let encrypted = encrypt_outputs(self.chain, memo_outputs, rng)?;
        if encrypted
            .commitments()
            .iter()
            .any(|value| self.seen_commitments.contains(&value.to_bytes()))
            || encrypted
                .commitments()
                .iter()
                .map(|v| v.to_bytes())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != encrypted.commitments().len()
        {
            return Err(WalletError::DuplicateChainEffect.into());
        }
        let anchor = NoteAnchor {
            root: Hash256::from_bytes(self.note_tree.root().to_bytes()),
            leaf_count: self.note_tree.leaf_count(),
        };
        if anchor.leaf_count == 0 {
            return Err(WalletError::InvalidWitnessState.into());
        }
        let mut statement_nullifiers = [Scalar::ZERO; 2];
        let mut circuit_inputs = [InputWitness::default(), InputWitness::default()];
        for (slot, (nullifier, witness, _)) in inputs.into_iter().enumerate() {
            statement_nullifiers[slot] = nullifier;
            circuit_inputs[slot] = witness;
        }
        let mut statement_outputs = [Scalar::ZERO; 2];
        let mut circuit_outputs = [OutputWitness::default(), OutputWitness::default()];
        for (slot, (commitment, witness)) in encrypted
            .commitments()
            .iter()
            .copied()
            .zip(output_witnesses)
            .enumerate()
        {
            statement_outputs[slot] = commitment;
            circuit_outputs[slot] = witness;
        }
        let memo = encrypted.memo().to_vec();
        let circuit = SpendCircuit {
            statement: SpendStatement {
                chain: self.chain,
                anchor: self.note_tree.root(),
                nullifiers: statement_nullifiers,
                output_notes: statement_outputs,
                burn_amount: 0,
                effect: Scalar::ZERO,
                memo: memo_scalar(&memo).map_err(WalletError::from)?,
            },
            inputs: circuit_inputs,
            outputs: circuit_outputs,
        };
        Ok(PreparedPrivateTransfer {
            circuit,
            anchor,
            selected_commitments,
            nullifiers,
            output_commitments: encrypted
                .commitments()
                .iter()
                .map(|v| v.to_bytes())
                .collect(),
            memo,
            amount,
            change,
        })
    }

    pub(super) fn select_transfer_notes(
        &self,
        amount: u64,
    ) -> Result<Vec<[u8; 32]>, PrivateTransferBuildError> {
        let mut available = self
            .notes
            .iter()
            .filter(|(_, note)| !note.spent && note.reservation_id.is_none())
            .map(|(commitment, note)| (note.received.opening.value, *commitment))
            .collect::<Vec<_>>();
        available.sort_unstable();
        let mut best: Option<(u64, usize, Vec<[u8; 32]>)> = available
            .iter()
            .filter(|(value, _)| *value >= amount)
            .map(|(value, commitment)| (*value - amount, 1, vec![*commitment]))
            .next();
        if available.len() >= 2 {
            let (mut left, mut right) = (0usize, available.len() - 1);
            while left < right {
                let Some(sum) = available[left].0.checked_add(available[right].0) else {
                    right -= 1;
                    continue;
                };
                if sum >= amount {
                    let mut commitments = vec![available[left].1, available[right].1];
                    commitments.sort_unstable();
                    let candidate = (sum - amount, 2, commitments);
                    if best.as_ref().is_none_or(|current| candidate < *current) {
                        best = Some(candidate);
                    }
                    right -= 1;
                } else {
                    left += 1;
                }
            }
        }
        best.map(|(_, _, commitments)| commitments)
            .ok_or(PrivateTransferBuildError::InsufficientSpendableNotes)
    }
}

pub(super) fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *bytes);
        if let Ok(value) = Scalar::from_bytes(*bytes) {
            if !value.is_zero() {
                return value;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Bn254;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_serialize::CanonicalSerialize;
    use dom_usdom_privacy::{
        chain_scalar, memo_scalar, privacy_policy_hash, verifier::SpendVerifier,
    };
    use dom_usdom_state::{
        derive_private_burn_id, encode_private_transfer_payload, inspect_private_burn_outputs,
        inspect_private_transfer_outputs, unsafe_test_only_transfer, verify_private_burn_payload,
        BridgeIdentity, BurnTimingPolicy, TransitionKind, TransitionPublicEffects,
        VerifiedTransition,
    };
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::{
        scan_memo, CanonicalWalletBlock, DurableWalletPersistenceError, PrivateBurnRequest,
        WalletPassphrase, WalletSealAuthorityError, WalletSealAuthorityState, WalletSnapshotSeal,
        WalletSnapshotSealAuthority, WalletTransitionObservation,
    };

    fn passphrase(value: &str) -> WalletPassphrase {
        WalletPassphrase::new(value.to_owned()).unwrap()
    }

    #[derive(Default)]
    struct TestSealAuthority {
        state: Option<WalletSnapshotSeal>,
        prepared: Option<WalletSnapshotSeal>,
        fail_commit_once: bool,
    }

    impl WalletSnapshotSealAuthority for TestSealAuthority {
        fn state(&mut self) -> Result<WalletSealAuthorityState, WalletSealAuthorityError> {
            Ok(WalletSealAuthorityState {
                committed: self.state,
                prepared: self.prepared,
            })
        }

        fn prepare(
            &mut self,
            expected: Option<WalletSnapshotSeal>,
            proposed: WalletSnapshotSeal,
        ) -> Result<(), WalletSealAuthorityError> {
            if self.state != expected || self.prepared.is_some() {
                return Err(WalletSealAuthorityError::Conflict);
            }
            self.prepared = Some(proposed);
            Ok(())
        }

        fn commit(&mut self, proposed: WalletSnapshotSeal) -> Result<(), WalletSealAuthorityError> {
            if self.prepared != Some(proposed) {
                return Err(WalletSealAuthorityError::Conflict);
            }
            if self.fail_commit_once {
                self.fail_commit_once = false;
                return Err(WalletSealAuthorityError::Unavailable);
            }
            self.state = Some(proposed);
            self.prepared = None;
            Ok(())
        }

        fn abort(&mut self, proposed: WalletSnapshotSeal) -> Result<(), WalletSealAuthorityError> {
            if self.prepared != Some(proposed) {
                return Err(WalletSealAuthorityError::Conflict);
            }
            self.prepared = None;
            Ok(())
        }
    }

    fn scalar(value: u64) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Scalar::from_bytes(bytes).unwrap()
    }

    #[test]
    fn preparation_selects_minimal_two_input_change_and_builds_exact_private_outputs() {
        let domain = [0xcc; 32];
        let chain = chain_scalar(domain, *privacy_policy_hash().as_bytes());
        let mut rng = StdRng::seed_from_u64(0x5553_444f_4d5f_4255);
        let wallet = WalletSecrets::generate(chain, &mut rng).unwrap();
        let recipient = WalletSecrets::generate(chain, &mut rng).unwrap();
        let initial = Hash256::from_bytes([0x41; 32]);
        let mut state = WalletState::new_empty(chain, 50, initial).unwrap();
        let mut parent = initial;
        let mut received_blocks = Vec::new();

        for (offset, values) in [vec![4u64, 7], vec![11u64]].into_iter().enumerate() {
            let memo_outputs = values
                .iter()
                .enumerate()
                .map(|(index, value)| MemoOutput {
                    recipient: wallet.address().unwrap(),
                    value: *value,
                    rho: scalar(70 + offset as u64 * 4 + index as u64),
                })
                .collect::<Vec<_>>();
            let encrypted = encrypt_outputs(chain, memo_outputs, &mut rng).unwrap();
            let outputs = encrypted
                .commitments()
                .iter()
                .map(|value| value.to_bytes())
                .collect::<Vec<_>>();
            let anchor = NoteAnchor {
                root: Hash256::from_bytes(scalar(80 + offset as u64).to_bytes()),
                leaf_count: 1,
            };
            let nullifier = scalar(90 + offset as u64).to_bytes();
            let payload = encode_private_transfer_payload(
                anchor,
                &[nullifier],
                &outputs,
                encrypted.memo(),
                &[0; 128],
            )
            .unwrap();
            let verified = VerifiedTransition::Transfer(unsafe_test_only_transfer(
                domain,
                anchor,
                vec![nullifier],
                outputs,
                memo_scalar(encrypted.memo()).unwrap().to_bytes(),
            ));
            let observation =
                WalletTransitionObservation::from_verified(&verified, Some(&payload)).unwrap();
            let identifier = Hash256::from_bytes([0x42 + offset as u8; 32]);
            let block = CanonicalWalletBlock {
                height: 51 + offset as u64,
                identifier,
                parent_identifier: parent,
                transitions: vec![observation],
            };
            state.apply_block(&wallet, block.clone()).unwrap();
            received_blocks.push(block);
            parent = identifier;
        }
        assert_eq!(state.available_balance(), 22);

        let single = state.select_transfer_notes(10).unwrap();
        assert_eq!(single.len(), 1);
        assert_eq!(state.notes[&single[0]].received.opening.value, 11);
        let pair = state.select_transfer_notes(12).unwrap();
        assert_eq!(pair.len(), 2);
        assert_eq!(
            pair.iter()
                .map(|commitment| state.notes[commitment].received.opening.value)
                .sum::<u64>(),
            15
        );
        assert!(matches!(
            state.select_transfer_notes(23),
            Err(PrivateTransferBuildError::InsufficientSpendableNotes)
        ));

        let prepared = state
            .prepare_private_transfer(&wallet, recipient.address().unwrap(), 12, &mut rng)
            .unwrap();
        assert_eq!(prepared.selected_commitments.len(), 2);
        assert_eq!(prepared.amount, 12);
        assert_eq!(prepared.change, 3);
        assert_eq!(prepared.anchor.leaf_count, 3);
        assert_eq!(prepared.circuit.statement.anchor, state.note_root());
        assert!(prepared.nullifiers.windows(2).all(|pair| pair[0] < pair[1]));
        let constraints = ConstraintSystem::new_ref();
        prepared
            .circuit
            .clone()
            .generate_constraints(constraints.clone())
            .unwrap();
        assert!(constraints.is_satisfied().unwrap());
        let public_outputs = prepared
            .output_commitments
            .iter()
            .map(|value| Scalar::from_bytes(*value).unwrap())
            .collect::<Vec<_>>();
        let recipient_notes = scan_memo(&recipient, &public_outputs, &prepared.memo).unwrap();
        let change_notes = scan_memo(&wallet, &public_outputs, &prepared.memo).unwrap();
        assert_eq!(recipient_notes.len(), 1);
        assert_eq!(recipient_notes[0].opening.value, 12);
        assert_eq!(change_notes.len(), 1);
        assert_eq!(change_notes[0].opening.value, 3);
        assert_eq!(state.available_balance(), 22);

        let parameters = Groth16::<Bn254>::generate_random_parameters_with_reduction(
            prepared.circuit.clone(),
            &mut rng,
        )
        .unwrap();
        let mut proving_key = Vec::new();
        parameters.serialize_compressed(&mut proving_key).unwrap();
        let mut verifying_key = Vec::new();
        parameters
            .vk
            .serialize_compressed(&mut verifying_key)
            .unwrap();
        let verifier = SpendVerifier::from_bytes(&verifying_key).unwrap();
        let prover = SpendProver::from_bytes(&proving_key, verifier.config_hash()).unwrap();

        let burn_directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                burn_directory.path(),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        let burn_base_path = burn_directory.path().join("burn-base.usdom");
        let burn_base_seal = state
            .save_encrypted_snapshot(
                &wallet,
                &burn_base_path,
                &passphrase("burn builder base password"),
                1,
                None,
            )
            .unwrap();
        let mut burn_state = WalletState::load_encrypted_snapshot(
            &burn_base_path,
            &passphrase("burn builder base password"),
            burn_base_seal,
        )
        .unwrap()
        .state;
        let mut ethereum_chain_id = [0u8; 32];
        ethereum_chain_id[31] = 1;
        let bridge = BridgeIdentity {
            dom_domain: domain,
            ethereum_genesis_validators_root: [0x91; 32],
            ethereum_chain_id,
            ethereum_checkpoint_policy_hash: [0x92; 32],
            ethereum_deposit_policy_hash: [0x93; 32],
            privacy_policy_hash: *privacy_policy_hash().as_bytes(),
            privacy_verifier_config_hash: *verifier.config_hash().as_bytes(),
            reserve: [0x94; 20],
            burn_timing: BurnTimingPolicy {
                withdrawal_delay_secs: 24 * 60 * 60,
                min_execution_window_secs: 60 * 60,
                max_certificate_lifetime_secs: 7 * 24 * 60 * 60,
                relay_safety_margin_secs: 2 * 24 * 60 * 60,
                max_ethereum_anchor_age_secs: 24 * 60 * 60,
                max_dom_clock_lead_secs: 2 * 60 * 60,
            },
        };
        let built_burn = burn_state
            .build_private_burn(
                &wallet,
                &prover,
                PrivateBurnRequest {
                    bridge,
                    recipient: [0x95; 20],
                    amount: 12,
                    authenticated_ethereum_timestamp: 1_800_000_000,
                },
                &mut rng,
            )
            .unwrap();
        assert_eq!(built_burn.record().amount, 12);
        assert_eq!(built_burn.record().valid_until, 1_800_604_800);
        assert_eq!(
            built_burn.record().burn_id,
            derive_private_burn_id(
                bridge,
                built_burn.nullifiers(),
                [0x95; 20],
                12,
                1_800_604_800,
            )
            .unwrap()
        );
        assert_eq!(built_burn.change(), 3);
        assert_eq!(built_burn.change_commitments().len(), 1);
        assert_eq!(burn_state.available_balance(), 7);
        assert_eq!(burn_state.pending_private_burns().len(), 1);
        let verified_burn =
            verify_private_burn_payload(bridge, &verifier, built_burn.payload()).unwrap();
        let burn_observation =
            WalletTransitionObservation::from_verified(&verified_burn, Some(built_burn.payload()))
                .unwrap();
        let burn_snapshot_path = burn_directory.path().join("pending-burn.usdom");
        let burn_snapshot_seal = burn_state
            .save_encrypted_snapshot(
                &wallet,
                &burn_snapshot_path,
                &passphrase("pending burn password"),
                1,
                None,
            )
            .unwrap();
        let mut burn_state = WalletState::load_encrypted_snapshot(
            &burn_snapshot_path,
            &passphrase("pending burn password"),
            burn_snapshot_seal,
        )
        .unwrap()
        .state;
        assert_eq!(
            burn_state
                .pending_private_burn_payload(built_burn.transition_id())
                .unwrap(),
            built_burn.payload()
        );
        let mut burn_authorized_state = WalletState::load_encrypted_snapshot(
            &burn_snapshot_path,
            &passphrase("pending burn password"),
            burn_snapshot_seal,
        )
        .unwrap()
        .state;
        let burn_authorized_path = burn_directory.path().join("authorized-burn.usdom");
        let mut burn_authority = TestSealAuthority::default();
        let (authorized_burn_seal, burn_permit) = burn_authorized_state
            .persist_pending_burn_for_submission(
                &wallet,
                built_burn.transition_id(),
                &burn_authorized_path,
                &passphrase("authorized burn password"),
                None,
                &mut burn_authority,
            )
            .unwrap();
        assert_eq!(burn_permit.transition_id(), built_burn.transition_id());
        assert_eq!(burn_permit.snapshot_seal(), authorized_burn_seal);
        assert!(matches!(
            burn_authorized_state.cancel_pending_private_burn(built_burn.transition_id()),
            Err(crate::PrivateBurnBuildError::PendingBurnAuthorized)
        ));
        let loaded_authorized_burn = WalletState::load_encrypted_snapshot(
            &burn_authorized_path,
            &passphrase("authorized burn password"),
            authorized_burn_seal,
        )
        .unwrap();
        let reissued_burn_permit = loaded_authorized_burn
            .pending_burn_submission_permit(built_burn.transition_id(), &mut burn_authority)
            .unwrap();
        assert_eq!(
            reissued_burn_permit.transition_id(),
            built_burn.transition_id()
        );
        assert_eq!(reissued_burn_permit.snapshot_seal(), authorized_burn_seal);
        let burn_block_id = Hash256::from_bytes([0x96; 32]);
        burn_state
            .apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: burn_state.tip_height() + 1,
                    identifier: burn_block_id,
                    parent_identifier: burn_state.tip_identifier(),
                    transitions: vec![burn_observation],
                },
            )
            .unwrap();
        assert!(burn_state.pending_private_burns()[0].all_inputs_canonically_spent);
        assert!(burn_state.pending_private_burns()[0].exact_payload_canonical);
        burn_state.rollback_tip(burn_block_id).unwrap();
        assert!(!burn_state.pending_private_burns()[0].exact_payload_canonical);
        burn_state
            .cancel_pending_private_burn(built_burn.transition_id())
            .unwrap();
        assert_eq!(burn_state.available_balance(), 22);
        let exact_burn = burn_state
            .build_private_burn(
                &wallet,
                &prover,
                PrivateBurnRequest {
                    bridge,
                    recipient: [0x97; 20],
                    amount: 11,
                    authenticated_ethereum_timestamp: 1_800_000_001,
                },
                &mut rng,
            )
            .unwrap();
        assert_eq!(exact_burn.change(), 0);
        assert!(exact_burn.change_commitments().is_empty());
        assert!(inspect_private_burn_outputs(exact_burn.payload())
            .unwrap()
            .encrypted_memo
            .is_empty());
        verify_private_burn_payload(bridge, &verifier, exact_burn.payload()).unwrap();
        burn_state
            .cancel_pending_private_burn(exact_burn.transition_id())
            .unwrap();
        assert_eq!(burn_state.available_balance(), 22);

        let built = state
            .build_private_transfer(&wallet, &prover, recipient.address().unwrap(), 12, &mut rng)
            .unwrap();
        assert_ne!(built.transition_id(), Hash256::ZERO);
        assert_eq!(built.amount(), 12);
        assert_eq!(built.change(), 3);
        let observed = inspect_private_transfer_outputs(built.payload()).unwrap();
        assert_eq!(observed.nullifiers, built.nullifiers());
        assert_eq!(observed.output_notes, built.output_commitments());
        let built_outputs = observed
            .output_notes
            .iter()
            .map(|value| Scalar::from_bytes(*value).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            scan_memo(&recipient, &built_outputs, observed.encrypted_memo).unwrap()[0]
                .opening
                .value,
            12
        );
        assert_eq!(state.available_balance(), 7);
        assert_eq!(state.pending_private_transfers().len(), 1);
        assert_eq!(
            state.pending_private_transfers()[0].canonical_nullifier_count,
            0
        );
        assert_eq!(
            state
                .pending_private_transfer_payload(built.transition_id())
                .unwrap(),
            built.payload()
        );
        assert_eq!(
            state
                .note_summaries()
                .iter()
                .filter(|note| note.reservation_id == Some(built.transition_id()))
                .count(),
            2
        );
        assert!(matches!(
            state.select_transfer_notes(12),
            Err(PrivateTransferBuildError::InsufficientSpendableNotes)
        ));

        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        let snapshot = directory.path().join("reserved.usdom");
        let mut authority = TestSealAuthority {
            fail_commit_once: true,
            ..TestSealAuthority::default()
        };
        assert!(matches!(
            state.persist_pending_transfer_for_submission(
                &wallet,
                built.transition_id(),
                &snapshot,
                &passphrase("reservation test password"),
                None,
                &mut authority,
            ),
            Err(DurableWalletPersistenceError::RecoveryRequired)
        ));
        assert!(authority.prepared.is_some());
        let mut restored = WalletState::reconcile_encrypted_snapshot_authority(
            &snapshot,
            &passphrase("reservation test password"),
            &mut authority,
        )
        .unwrap()
        .unwrap();
        let permit = restored
            .pending_transfer_submission_permit(built.transition_id(), &mut authority)
            .unwrap();
        assert_eq!(permit.transition_id(), built.transition_id());
        assert_eq!(permit.snapshot_seal(), restored.seal);
        assert_eq!(restored.state.pending_private_transfers().len(), 1);
        assert!(restored.state.pending_private_transfers()[0].submission_authorized);
        assert_eq!(restored.state.available_balance(), 7);
        assert!(matches!(
            restored
                .state
                .cancel_pending_private_transfer(built.transition_id()),
            Err(PrivateTransferBuildError::PendingTransferAuthorized)
        ));
        assert_eq!(restored.state.available_balance(), 7);

        // A reorganization that removes one selected input must retain the
        // signed intent. If that exact note returns, its reservation is
        // restored instead of allowing a conflicting local spend.
        state.rollback_tip(received_blocks[1].identifier).unwrap();
        assert_eq!(state.pending_private_transfers().len(), 1);
        assert_eq!(state.available_balance(), 7);
        assert_eq!(
            state
                .note_summaries()
                .iter()
                .filter(|note| note.reservation_id == Some(built.transition_id()))
                .count(),
            1
        );
        let reorg_snapshot = directory.path().join("reserved-after-reorg.usdom");
        let reorg_seal = state
            .save_encrypted_snapshot(
                &wallet,
                &reorg_snapshot,
                &passphrase("reservation reorg password"),
                1,
                None,
            )
            .unwrap();
        let reorg_restored = WalletState::load_encrypted_snapshot(
            &reorg_snapshot,
            &passphrase("reservation reorg password"),
            reorg_seal,
        )
        .unwrap();
        assert_eq!(reorg_restored.state.pending_private_transfers().len(), 1);
        assert_eq!(reorg_restored.state.available_balance(), 7);
        state
            .apply_block(&wallet, received_blocks[1].clone())
            .unwrap();
        assert_eq!(
            state
                .note_summaries()
                .iter()
                .filter(|note| note.reservation_id == Some(built.transition_id()))
                .count(),
            2
        );

        let confirmation_id = Hash256::from_bytes([0x44; 32]);
        let confirmation = CanonicalWalletBlock {
            height: state.tip_height() + 1,
            identifier: confirmation_id,
            parent_identifier: state.tip_identifier(),
            transitions: vec![WalletTransitionObservation {
                effects: TransitionPublicEffects {
                    kind: TransitionKind::Burn,
                    nullifiers: built.nullifiers().to_vec(),
                    note_commitments: Vec::new(),
                    memo_commitment: Some([0; 32]),
                },
                encrypted_memo: Vec::new(),
                private_payload_id: None,
            }],
        };
        state.apply_block(&wallet, confirmation.clone()).unwrap();
        assert!(state.pending_private_transfers()[0].all_inputs_canonically_spent);
        assert!(!state.pending_private_transfers()[0].exact_payload_canonical);
        assert!(matches!(
            state.cancel_pending_private_transfer(built.transition_id()),
            Err(PrivateTransferBuildError::PendingTransferObserved)
        ));
        state.rollback_tip(confirmation_id).unwrap();
        assert!(!state.pending_private_transfers()[0].all_inputs_canonically_spent);
        assert!(!state.pending_private_transfers()[0].exact_payload_canonical);
        assert_eq!(state.available_balance(), 7);
        let exact_verified = VerifiedTransition::Transfer(unsafe_test_only_transfer(
            domain,
            built.anchor(),
            built.nullifiers().to_vec(),
            built.output_commitments().to_vec(),
            memo_scalar(
                inspect_private_transfer_outputs(built.payload())
                    .unwrap()
                    .encrypted_memo,
            )
            .unwrap()
            .to_bytes(),
        ));
        let exact_observation =
            WalletTransitionObservation::from_verified(&exact_verified, Some(built.payload()))
                .unwrap();
        state
            .apply_block(
                &wallet,
                CanonicalWalletBlock {
                    height: state.tip_height() + 1,
                    identifier: Hash256::from_bytes([0x45; 32]),
                    parent_identifier: state.tip_identifier(),
                    transitions: vec![exact_observation],
                },
            )
            .unwrap();
        assert!(state.pending_private_transfers()[0].all_inputs_canonically_spent);
        assert!(state.pending_private_transfers()[0].exact_payload_canonical);
        assert!(matches!(
            state.cancel_pending_private_transfer(built.transition_id()),
            Err(PrivateTransferBuildError::PendingTransferObserved)
        ));
    }
}
