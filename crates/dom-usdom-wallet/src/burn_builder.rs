//! Proof-backed private burns and persistent input reservations.

use dom_core::Hash256;
use dom_usdom_privacy::{
    chain_scalar,
    circuit::{InputWitness, OutputWitness, SpendCircuit, SpendStatement},
    memo_scalar, privacy_policy_hash, Scalar,
};
use dom_usdom_prover::{ProverError, SpendProver};
use dom_usdom_state::{
    derive_private_burn_id, encode_private_burn_payload, private_burn_effect_scalar,
    private_burn_payload_id, BridgeIdentity, BurnRecord, NoteAnchor, UsdomStateError,
};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

use super::{
    builder::random_scalar, encrypt_outputs, MemoOutput, WalletError, WalletSecrets, WalletState,
};

pub(super) struct PendingPrivateBurn {
    pub(super) anchor: NoteAnchor,
    pub(super) created_at_tip: Hash256,
    pub(super) created_at_height: u64,
    pub(super) selected_commitments: Vec<[u8; 32]>,
    pub(super) nullifiers: Vec<[u8; 32]>,
    pub(super) payload: Vec<u8>,
    pub(super) record: BurnRecord,
    pub(super) submission_authorized: bool,
}

/// Public state of one persistently reserved private burn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPrivateBurnSummary {
    /// Identifier of the exact randomized burn proof payload.
    pub transition_id: Hash256,
    /// Public immutable Ethereum payout obligation.
    pub record: BurnRecord,
    /// Tip at which its membership witnesses were constructed.
    pub created_at_tip: Hash256,
    /// Height of that tip.
    pub created_at_height: u64,
    /// Exact note-tree proof anchor.
    pub anchor: NoteAnchor,
    /// Reserved owned note commitments.
    pub selected_commitments: Vec<[u8; 32]>,
    /// Canonical public nullifiers.
    pub nullifiers: Vec<[u8; 32]>,
    /// Number of its nullifiers present in canonical wallet state.
    pub canonical_nullifier_count: usize,
    /// Whether every input is canonically spent.
    pub all_inputs_canonically_spent: bool,
    /// Whether this exact randomized burn payload is canonical.
    pub exact_payload_canonical: bool,
    /// Whether a committed snapshot authorized network submission.
    pub submission_authorized: bool,
}

/// Public bridge-bound request used to construct one private burn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateBurnRequest {
    /// Immutable bridge identity and burn timing policy.
    pub bridge: BridgeIdentity,
    /// Public Ethereum payout address.
    pub recipient: [u8; 20],
    /// Amount removed from native private circulation.
    pub amount: u64,
    /// Latest authenticated finalized Ethereum execution timestamp.
    pub authenticated_ethereum_timestamp: u64,
}

/// Failure while constructing or managing a private burn.
#[derive(Debug, Error)]
pub enum PrivateBurnBuildError {
    /// Wallet identity, recipient, note, witness, or change construction failed.
    #[error("invalid USDOM private burn request: {0}")]
    Wallet(#[from] WalletError),
    /// No one- or two-note selection can cover the burn amount.
    #[error("insufficient USDOM value spendable within the two-input circuit")]
    InsufficientSpendableNotes,
    /// Amount or deadline arithmetic overflowed.
    #[error("USDOM private burn arithmetic overflow")]
    ArithmeticOverflow,
    /// Bridge identity or public obligation is invalid.
    #[error("invalid USDOM private burn bridge obligation: {0}")]
    State(#[from] UsdomStateError),
    /// Offline proof construction or mandatory self-verification failed.
    #[error("USDOM private burn proof failed: {0}")]
    Prover(#[from] ProverError),
    /// A selected note or exact payload is already reserved.
    #[error("USDOM private burn input is already reserved")]
    AlreadyReserved,
    /// No pending burn has the requested identifier.
    #[error("unknown USDOM pending private burn")]
    UnknownPendingBurn,
    /// Cancellation followed canonical observation of a selected nullifier.
    #[error("cannot cancel a canonically observed USDOM private burn")]
    PendingBurnObserved,
    /// Cancellation followed durable submission authorization.
    #[error("cannot cancel a USDOM private burn authorized for submission")]
    PendingBurnAuthorized,
}

/// Complete canonical private-burn bytes and public payout metadata.
pub struct BuiltPrivateBurn {
    payload: Vec<u8>,
    transition_id: Hash256,
    anchor: NoteAnchor,
    selected_commitments: Vec<[u8; 32]>,
    nullifiers: Vec<[u8; 32]>,
    change_commitments: Vec<[u8; 32]>,
    record: BurnRecord,
    change: u64,
}

impl BuiltPrivateBurn {
    /// Canonical payload accepted by native private-burn verification.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Domain-separated identifier of the exact randomized proof payload.
    pub fn transition_id(&self) -> Hash256 {
        self.transition_id
    }

    /// Exact public Ethereum payout obligation bound into the proof.
    pub fn record(&self) -> BurnRecord {
        self.record
    }

    /// Exact note-tree anchor under which inputs were proven.
    pub fn anchor(&self) -> NoteAnchor {
        self.anchor
    }

    /// Owned note commitments reserved by this intent.
    pub fn selected_commitments(&self) -> &[[u8; 32]] {
        &self.selected_commitments
    }

    /// Canonically ordered public nullifiers.
    pub fn nullifiers(&self) -> &[[u8; 32]] {
        &self.nullifiers
    }

    /// Private change-note commitments, empty for an exact-value burn.
    pub fn change_commitments(&self) -> &[[u8; 32]] {
        &self.change_commitments
    }

    /// Private change returned to this wallet.
    pub fn change(&self) -> u64 {
        self.change
    }
}

impl WalletState {
    /// Select at most two owned notes, construct private change, bind a fresh
    /// public payout obligation, prove conservation, and reserve every input.
    pub fn build_private_burn<R: RngCore + CryptoRng>(
        &mut self,
        wallet: &WalletSecrets,
        prover: &SpendProver,
        request: PrivateBurnRequest,
        rng: &mut R,
    ) -> Result<BuiltPrivateBurn, PrivateBurnBuildError> {
        let PrivateBurnRequest {
            bridge,
            recipient,
            amount,
            authenticated_ethereum_timestamp,
        } = request;
        let expected_chain = chain_scalar(bridge.dom_domain, bridge.privacy_policy_hash);
        if amount == 0
            || recipient == [0; 20]
            || authenticated_ethereum_timestamp == 0
            || wallet.chain != self.chain
            || self.chain != expected_chain
            || bridge.privacy_policy_hash != *privacy_policy_hash().as_bytes()
            || prover.verifier_config_hash().as_bytes() != &bridge.privacy_verifier_config_hash
        {
            return Err(WalletError::InvalidIdentity.into());
        }
        let valid_until = authenticated_ethereum_timestamp
            .checked_add(bridge.burn_timing.max_certificate_lifetime_secs)
            .ok_or(PrivateBurnBuildError::ArithmeticOverflow)?;
        let selected = self
            .select_transfer_notes(amount)
            .map_err(|_| PrivateBurnBuildError::InsufficientSpendableNotes)?;
        let total = selected.iter().try_fold(0u64, |sum, commitment| {
            let value = self
                .notes
                .get(commitment)
                .ok_or(PrivateBurnBuildError::InsufficientSpendableNotes)?
                .received
                .opening
                .value;
            sum.checked_add(value)
                .ok_or(PrivateBurnBuildError::ArithmeticOverflow)
        })?;
        let change = total
            .checked_sub(amount)
            .ok_or(PrivateBurnBuildError::InsufficientSpendableNotes)?;

        let mut inputs = Vec::with_capacity(selected.len());
        for commitment in &selected {
            let scalar = Scalar::from_bytes(*commitment).map_err(WalletError::from)?;
            let witness = self.spend_witness(wallet, scalar)?;
            let note = self
                .notes
                .get(commitment)
                .ok_or(PrivateBurnBuildError::InsufficientSpendableNotes)?;
            inputs.push((
                wallet.nullifier_for(&note.received.opening)?,
                witness,
                *commitment,
            ));
        }
        inputs.sort_by_key(|(nullifier, _, _)| nullifier.to_bytes());
        let selected_commitments = inputs
            .iter()
            .map(|(_, _, commitment)| *commitment)
            .collect::<Vec<_>>();
        let nullifiers = inputs
            .iter()
            .map(|(nullifier, _, _)| nullifier.to_bytes())
            .collect::<Vec<_>>();
        let burn_id = derive_private_burn_id(bridge, &nullifiers, recipient, amount, valid_until)?;
        let mut request_id = random_identifier(rng);
        while request_id == burn_id {
            request_id = random_identifier(rng);
        }
        let mut record = BurnRecord {
            burn_id,
            request_id,
            amount,
            recipient,
            ethereum_chain_id: bridge.ethereum_chain_id,
            reserve: bridge.reserve,
            valid_until,
            obligation_commitment: [0; 32],
        };
        record.obligation_commitment = record.expected_obligation_commitment(bridge.dom_domain);
        let effect = private_burn_effect_scalar(bridge, record)?;

        let (change_commitments, memo, output_witnesses) = if change == 0 {
            (Vec::new(), Vec::new(), Vec::new())
        } else {
            let output = MemoOutput {
                recipient: wallet.address()?,
                value: change,
                rho: random_scalar(rng),
            };
            let witness = OutputWitness {
                enabled: true,
                value: output.value,
                owner: output.recipient.owner(),
                rho: output.rho,
            };
            let encrypted = encrypt_outputs(self.chain, vec![output], rng)?;
            let commitments = encrypted
                .commitments()
                .iter()
                .map(|value| value.to_bytes())
                .collect::<Vec<_>>();
            if commitments
                .iter()
                .any(|value| self.seen_commitments.contains(value))
            {
                return Err(WalletError::DuplicateChainEffect.into());
            }
            (commitments, encrypted.memo().to_vec(), vec![witness])
        };
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
        for (slot, (commitment, witness)) in change_commitments
            .iter()
            .map(|value| Scalar::from_bytes(*value))
            .collect::<Result<Vec<_>, _>>()
            .map_err(WalletError::from)?
            .into_iter()
            .zip(output_witnesses)
            .enumerate()
        {
            statement_outputs[slot] = commitment;
            circuit_outputs[slot] = witness;
        }
        let statement_memo = if memo.is_empty() {
            Scalar::ZERO
        } else {
            memo_scalar(&memo).map_err(WalletError::from)?
        };
        let circuit = SpendCircuit {
            statement: SpendStatement {
                chain: self.chain,
                anchor: self.note_tree.root(),
                nullifiers: statement_nullifiers,
                output_notes: statement_outputs,
                burn_amount: amount,
                effect,
                memo: statement_memo,
            },
            inputs: circuit_inputs,
            outputs: circuit_outputs,
        };
        let proof = prover.prove(circuit, rng)?;
        let payload = encode_private_burn_payload(
            anchor,
            &nullifiers,
            &change_commitments,
            record,
            &memo,
            &proof,
        )?;
        let transition_id = private_burn_payload_id(&payload);
        if self.pending_burns.contains_key(transition_id.as_bytes())
            || selected_commitments.iter().any(|commitment| {
                self.notes
                    .get(commitment)
                    .is_none_or(|note| note.spent || note.reservation_id.is_some())
            })
        {
            return Err(PrivateBurnBuildError::AlreadyReserved);
        }
        for commitment in &selected_commitments {
            let Some(note) = self.notes.get_mut(commitment) else {
                return Err(PrivateBurnBuildError::AlreadyReserved);
            };
            note.reservation_id = Some(transition_id);
        }
        self.pending_burns.insert(
            *transition_id.as_bytes(),
            PendingPrivateBurn {
                anchor,
                created_at_tip: self.tip_identifier,
                created_at_height: self.tip_height,
                selected_commitments: selected_commitments.clone(),
                nullifiers: nullifiers.clone(),
                payload: payload.clone(),
                record,
                submission_authorized: false,
            },
        );
        Ok(BuiltPrivateBurn {
            payload,
            transition_id,
            anchor,
            selected_commitments,
            nullifiers,
            change_commitments,
            record,
            change,
        })
    }

    /// Summaries of every pending private burn in identifier order.
    pub fn pending_private_burns(&self) -> Vec<PendingPrivateBurnSummary> {
        self.pending_burns
            .iter()
            .map(|(transition_id, pending)| {
                let canonical_nullifier_count = pending
                    .nullifiers
                    .iter()
                    .filter(|value| self.seen_nullifiers.contains(*value))
                    .count();
                PendingPrivateBurnSummary {
                    transition_id: Hash256::from_bytes(*transition_id),
                    record: pending.record,
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

    /// Exact canonical bytes retained for a pending private burn.
    pub fn pending_private_burn_payload(&self, transition_id: Hash256) -> Option<&[u8]> {
        self.pending_burns
            .get(transition_id.as_bytes())
            .map(|pending| pending.payload.as_slice())
    }

    #[cfg(feature = "rpc-client")]
    pub(crate) fn authorized_private_burn_payload(&self, transition_id: Hash256) -> Option<&[u8]> {
        self.pending_burns
            .get(transition_id.as_bytes())
            .filter(|pending| pending.submission_authorized)
            .map(|pending| pending.payload.as_slice())
    }

    /// Cancel a never-authorized burn while none of its nullifiers is canonical.
    pub fn cancel_pending_private_burn(
        &mut self,
        transition_id: Hash256,
    ) -> Result<(), PrivateBurnBuildError> {
        let pending = self
            .pending_burns
            .get(transition_id.as_bytes())
            .ok_or(PrivateBurnBuildError::UnknownPendingBurn)?;
        if pending
            .nullifiers
            .iter()
            .any(|value| self.seen_nullifiers.contains(value))
        {
            return Err(PrivateBurnBuildError::PendingBurnObserved);
        }
        if pending.submission_authorized {
            return Err(PrivateBurnBuildError::PendingBurnAuthorized);
        }
        let selected = pending.selected_commitments.clone();
        self.pending_burns.remove(transition_id.as_bytes());
        for commitment in selected {
            if let Some(note) = self.notes.get_mut(&commitment) {
                if note.reservation_id == Some(transition_id) {
                    note.reservation_id = None;
                }
            }
        }
        Ok(())
    }
}

fn random_identifier<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
    loop {
        let mut value = [0u8; 32];
        rng.fill_bytes(&mut value);
        if value != [0; 32] {
            return value;
        }
    }
}
