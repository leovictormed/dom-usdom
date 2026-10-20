//! Native USDOM state/undo persistence through the real LMDB block boundary.
//!
//! Proof capabilities are test-only fixtures. The exercised state transition,
//! root, canonical entries, undo codec, block commit, and reorg transaction are
//! the production-shaped components.

mod common;

use common::open_test_store;
use dom_core::MAX_FUTURE_BLOCK_TIME;
use dom_store::ConsensusStateUpdate;
use dom_usdom_state::{
    unsafe_test_only_ethereum_checkpoint, unsafe_test_only_issuance, unsafe_test_only_transfer,
    BatchUndo, BlockContext, BridgeIdentity, BurnTimingPolicy, EthereumAnchor, NativeUsdomState,
    VerifiedTransition,
};
use tempfile::TempDir;

const DOMAIN: [u8; 32] = [0x11; 32];
const UNDO_PREFIX: &[u8] = b"usdom-undo/v3/";
const BLOCK_TIMESTAMP: u64 = 1_800_000_000;

fn bridge() -> BridgeIdentity {
    let mut ethereum_chain_id = [0; 32];
    ethereum_chain_id[30..].copy_from_slice(&31337u16.to_be_bytes());
    BridgeIdentity {
        dom_domain: DOMAIN,
        ethereum_genesis_validators_root: [5; 32],
        ethereum_chain_id,
        ethereum_checkpoint_policy_hash: [0x43; 32],
        ethereum_deposit_policy_hash: [0x44; 32],
        privacy_policy_hash: *dom_usdom_privacy::privacy_policy_hash().as_bytes(),
        privacy_verifier_config_hash: [0x48; 32],
        reserve: [0x66; 20],
        burn_timing: BurnTimingPolicy {
            withdrawal_delay_secs: 86_400,
            min_execution_window_secs: 3_600,
            max_certificate_lifetime_secs: 604_800,
            relay_safety_margin_secs: 3_600,
            max_ethereum_anchor_age_secs: 1_800,
            max_dom_clock_lead_secs: MAX_FUTURE_BLOCK_TIME,
        },
    }
}

fn context() -> BlockContext {
    BlockContext {
        timestamp: BLOCK_TIMESTAMP,
    }
}

fn hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn undo_key(block_hash: [u8; 32]) -> Vec<u8> {
    let mut key = UNDO_PREFIX.to_vec();
    key.extend_from_slice(&block_hash);
    key
}

fn state_updates(
    next: &NativeUsdomState,
    previous: &NativeUsdomState,
    block_hash: [u8; 32],
    undo: &BatchUndo,
) -> Vec<ConsensusStateUpdate> {
    let mut updates: Vec<_> = next
        .storage_delta_from(previous)
        .unwrap()
        .into_iter()
        .map(|update| ConsensusStateUpdate {
            key: update.key,
            value: update.value,
        })
        .collect();
    updates.push(ConsensusStateUpdate {
        key: undo_key(block_hash),
        value: Some(undo.to_bytes().unwrap()),
    });
    updates
}

fn persisted_state(store: &dom_store::DomStore) -> NativeUsdomState {
    let entries = store
        .read_all_consensus_state_raw()
        .unwrap()
        .into_iter()
        .filter(|(key, _)| key.starts_with(b"usdom/v3/"))
        .collect();
    NativeUsdomState::restore_entries(bridge(), &entries).unwrap()
}

#[test]
fn connect_restart_and_reorg_restore_exact_native_state_and_undo() {
    let dir = TempDir::new().unwrap();
    let block0 = hash(0xa0);
    let block1 = hash(0xa1);
    let block2 = hash(0xa2);
    let block3 = hash(0xa3);
    let empty = NativeUsdomState::new(bridge()).unwrap();
    let mut issued = empty.clone();
    let issuance = VerifiedTransition::Issue(unsafe_test_only_issuance(
        DOMAIN,
        [1; 32],
        [2; 32],
        1_000_000,
        EthereumAnchor {
            genesis_validators_root: [5; 32],
            execution_block_number: 20_000_000,
            execution_block_hash: [3; 32],
            execution_block_timestamp: BLOCK_TIMESTAMP - 60,
            beacon_slot: 16_000_000,
            beacon_root: [4; 32],
        },
    ));
    let (_receipt1, undo1) = issued.apply_batch(context(), &[issuance]).unwrap();

    {
        let store = open_test_store(dir.path());
        let activation_updates: Vec<_> = empty
            .export_entries()
            .into_iter()
            .map(|(key, value)| ConsensusStateUpdate {
                key,
                value: Some(value),
            })
            .collect();
        store
            .commit_block_with_consensus_state(
                &block0,
                0,
                b"header-0",
                b"body-0",
                &[],
                &[],
                &[],
                &activation_updates,
            )
            .unwrap();
        store
            .commit_block_with_consensus_state(
                &block1,
                1,
                b"header-1",
                b"body-1",
                &[],
                &[],
                &[],
                &state_updates(&issued, &empty, block1, &undo1),
            )
            .unwrap();
        assert_eq!(persisted_state(&store).state_root(), issued.state_root());
    }

    let store = open_test_store(dir.path());
    let reopened = persisted_state(&store);
    assert_eq!(reopened.state_root(), issued.state_root());
    assert_eq!(
        BatchUndo::from_bytes(
            &store
                .get_consensus_state(&undo_key(block1))
                .unwrap()
                .unwrap()
        )
        .unwrap()
        .before_root(),
        empty.state_root()
    );

    let mut transferred = reopened.clone();
    let transfer = VerifiedTransition::Transfer(unsafe_test_only_transfer(
        DOMAIN,
        transferred.note_anchor(),
        vec![[5; 32]],
        vec![[6; 32], [7; 32]],
        [0x0f; 32],
    ));
    let (receipt2, undo2) = transferred.apply_batch(context(), &[transfer]).unwrap();
    store
        .commit_block_with_consensus_state(
            &block2,
            2,
            b"header-2",
            b"body-2",
            &[],
            &[],
            &[],
            &state_updates(&transferred, &reopened, block2, &undo2),
        )
        .unwrap();
    assert_eq!(
        persisted_state(&store).state_root(),
        transferred.state_root()
    );

    let mut anchored = transferred.clone();
    let anchor = EthereumAnchor {
        genesis_validators_root: [5; 32],
        execution_block_number: 20_000_100,
        execution_block_hash: [8; 32],
        execution_block_timestamp: BLOCK_TIMESTAMP + 60,
        beacon_slot: 16_000_100,
        beacon_root: [9; 32],
    };
    let checkpoint = VerifiedTransition::EthereumCheckpoint(unsafe_test_only_ethereum_checkpoint(
        DOMAIN, anchor,
    ));
    let (receipt3, undo3) = anchored.apply_batch(context(), &[checkpoint]).unwrap();
    store
        .commit_block_with_consensus_state(
            &block3,
            3,
            b"header-3",
            b"body-3",
            &[],
            &[],
            &[],
            &state_updates(&anchored, &transferred, block3, &undo3),
        )
        .unwrap();
    assert_eq!(persisted_state(&store).ethereum_anchor(), Some(anchor));

    let decoded_checkpoint_undo = BatchUndo::from_bytes(
        &store
            .get_consensus_state(&undo_key(block3))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let mut checkpoint_reverted = anchored.clone();
    checkpoint_reverted
        .revert_batch(&decoded_checkpoint_undo, receipt3.header_commitment)
        .unwrap();
    assert_eq!(checkpoint_reverted.state_root(), transferred.state_root());
    let mut checkpoint_reverse_updates: Vec<_> = checkpoint_reverted
        .storage_delta_from(&anchored)
        .unwrap()
        .into_iter()
        .map(|update| ConsensusStateUpdate {
            key: update.key,
            value: update.value,
        })
        .collect();
    checkpoint_reverse_updates.push(ConsensusStateUpdate {
        key: undo_key(block3),
        value: None,
    });
    store
        .apply_reorg_with_consensus_state(
            &block2,
            &[(3, None)],
            &[],
            &[],
            &checkpoint_reverse_updates,
        )
        .unwrap();
    assert_eq!(
        persisted_state(&store).state_root(),
        transferred.state_root()
    );

    let decoded_undo = BatchUndo::from_bytes(
        &store
            .get_consensus_state(&undo_key(block2))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let mut reverted = transferred.clone();
    reverted
        .revert_batch(&decoded_undo, receipt2.header_commitment)
        .unwrap();
    assert_eq!(reverted.state_root(), issued.state_root());
    let mut reverse_updates: Vec<_> = reverted
        .storage_delta_from(&transferred)
        .unwrap()
        .into_iter()
        .map(|update| ConsensusStateUpdate {
            key: update.key,
            value: update.value,
        })
        .collect();
    reverse_updates.push(ConsensusStateUpdate {
        key: undo_key(block2),
        value: None,
    });
    store
        .apply_reorg_with_consensus_state(&block1, &[(2, None)], &[], &[], &reverse_updates)
        .unwrap();
    assert_eq!(store.get_chain_tip().unwrap(), Some(block1));
    assert_eq!(persisted_state(&store).state_root(), issued.state_root());
    assert_eq!(store.get_consensus_state(&undo_key(block2)).unwrap(), None);
    assert!(store
        .get_consensus_state(&undo_key(block1))
        .unwrap()
        .is_some());
}
