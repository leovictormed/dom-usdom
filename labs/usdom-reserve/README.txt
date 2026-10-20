USDOM Reserve v3 — prototype integration in dom-protocol

This module contains the hardened Solidity reserve, EIP-712 SDK, prototype
monitor and tests. It is additive and has not been deployed. It does not add
USDOM to the native monetary consensus. Mainnet readiness is false.

contracts/USDOMReserve.sol remains the quorum-only prototype and rejects chain
ID 1. contracts/USDOMProofReserve.sol is the separate proof-authorized boundary:
it contains no notary fallback and pins an immutable verifier/configuration, but
its production hashes intentionally remain zero until the native burn/finality
proof exists and is audited. See docs/PROOF-RESERVE-SPEC.txt.

The operator selected Ethereum mainnet and the intended USDT address recorded
in config/operator-intent.json. Governance/guardian multisigs, notary operators,
quorum, limits, delays, DOM domain and production finality remain undefined.
Quorum attestations are authorized for the prototype only. The operator now
requires Ethereum-verifiable DOM consensus proofs for production, a distinct
native USDOM asset and private native transfers without changing DOM monetary
policy. This phase is feasibility/design only; no real deposits or deployment
are authorized. See docs/NATIVE-USDOM-DESIGN.txt and config/production-requirements.json.
USDOM issuance must use eligible USDT deposits exclusively, with no USDOM mining
reward. Issuance does not settle burn finality. The operator requested comparison
before selection; see docs/FINALITY-COMPARISON.txt. Ethereum checkpoints
recognized by DOM were selected for an isolated proof of concept. That research
choice is not a production finality approval.

Provenance
Target: https://github.com/sorenplanck/dom-protocol
Base: mainnetswap, d536cf44d04c5c51611ad174f2fa5c8c3ac40f0c
Prototype reference: https://github.com/sorenplanck/atualia
Reference commit: 7925ea2a701f93e795591db7d0bd0635c14d886f
PROVENANCE.json identifies every imported source. The reference prototype's
README pins the same dom-protocol commit. Development branch integration is
not a release-tag approval for mainnet nodes.
LOCAL-CHANGES.json records deliberate changes after the initial import, including
the USDT policy checks, contract-only administrative roles and checked timestamp
conversions. Run python3 scripts/verify-import.py to verify them.

Build and test from this directory
Use Node 24.19.0, Foundry/Anvil 1.7.1 and native solc 0.8.37. OpenZeppelin 5.6.1
is vendored from the signed upstream tag recorded in DEPENDENCIES.json; ethers
6.17.0 is pinned in package-lock.json. No solc-js or Ganache.
The bytecode target is Cancun because OpenZeppelin 5.6.1 uses MCOPY; Ethereum
mainnet has supported Cancun opcodes since Dencun.
  npm ci --ignore-scripts
  forge test --offline --use /absolute/path/to/solc-0.8.37
  npm test
  FOUNDRY_PROFILE=deep forge test --offline --use /absolute/path/to/solc-0.8.37 \
    --fuzz-seed 0x5553444f4d20261015
Anvil must be on PATH or selected with USDOM_ANVIL. The EVM fixtures use local
chain ID 31337, public test keys and HostileToken. Never use these identities
or example limits as production parameters. Configuration validation rejects
missing parameters and does not certify readiness.

Mainnet release gates are fail closed and return a machine-readable blocker
inventory. They verify the exact deployment commitment, compiled production
pins, declared requirements, operator authorization and SHA-256-addressed
evidence files. A passing gate still requires reviewers to authenticate audit
authors and execute the runbook against finalized Ethereum state.
  npm run check:mainnet
  npm run check:real-funds
The checked-in unconfigured candidate must make both commands exit nonzero.

USDT compatibility and fork regression
This candidate now requires the USDT policy getters, including on local test
tokens. The quorum prototype's constructor and SDK reject Ethereum mainnet
(chain ID 1), even with the intended USDT address. Deposit, queue and execution fail closed if the token is paused,
deprecated, has nonzero fee settings or freezes the relevant funder/reserve/
recipient. A failed payout preserves the unpaid claim and outflow capacity.
Balance-delta checks remain mandatory; token policy checks do not replace them.
These checks cannot prevent Tether from freezing or confiscating funds later.
See docs/USDT-FORK.txt for the reproduced frozen-recipient bug and correction.
The optional fork suite executes against RPC-supplied Ethereum state locally:
  FOUNDRY_PROFILE=fork forge test --use /absolute/path/to/solc-0.8.37 \
    --fork-url <archive-read-RPC> --fork-block-number 26201446
The expected default block is 26201446. To intentionally validate another block,
set USDOM_FORK_BLOCK to that same number and record its hash/state separately.
The runtime hash is pinned in the suite; an unexpected code change is rejected.
The fixture checks Ethereum chain ID and runtime first, then changes only the
local VM chain ID to 31337 to exercise token transfers. A separate regression
asserts that deployment with the real USDT on chain ID 1 fails with PrototypeOnly.
No owner key is supplied; owner impersonation changes only the local fork.

Security properties and limits
Accepted certificates reserve credited collateral. Donations do not authorize
issuance. Paid burn/request IDs remain consumed. Rotation invalidates prior
epochs and resets reservations, never the actual outflow bucket. A blocked
recipient does not block other recipients solely by queue position. The shared
rate limiter still offers no fairness or deadline guarantee; expired claims
may require fresh quorum attestations.
Emergency recovery permanently revokes the active notaries. The monitor uses
pauseEpoch(expectedEpoch), so a delayed transaction cannot revoke a replacement
epoch. It records the certificate's observed epoch, falls back to operational
pause after a verified rotation, and never resumes automatically. See
scripts/candidate-monitor.mjs and docs/MONITOR.txt.
The prototype monitor checks normalized experimental-chain views. It does not
verify DOM consensus on Ethereum or prove native USDOM monetary integration.
Its Rust snapshot verifier remains an external pinned component from atualia.
No production daemon, multisig signer or deployment has been installed.

Current security validation (2026-10-16)
The combined revision passes 93/93 default Solidity tests. Deep testing uses
16,384 cases per fuzz property and 1,024 invariant runs at depth 128 (131,072
calls per invariant) for independent quorum accounting, recovery and proof-
reserve accounting/queue models. USDOMProofReserve has 95.21% line, 96.87%
statement, 95.65% branch and 100% function coverage in the targeted campaign.
Its optimized runtime is 11,612 bytes; the quorum prototype remains 17,162
bytes. Seven fork tests pass against the pinned Ethereum mainnet USDT state at
block 26201446, including both mainnet deployment guards. All 32 SDK/monitor
tests pass, including exact Solidity/JavaScript proof-statement agreement and
fail-closed proof configuration. See docs/PROOF-RESERVE-HARDENING-2026-10-16.txt
and the matching results directory.

DOM checkpoint proof of concept (2026-10-17)
The feature-gated regtest experiment in crates/dom-chain now persists a chained
checkpoint statement and rejects a real fork-choice promotion whose common
ancestor would precede the anchor. The statement binds the DOM block and future
state commitment to asserted Ethereum finality, receipt, contract, verifier and
evidence identities. These external claims come from a trusted TEST ORACLE;
they are not authenticated. Normal builds are unchanged and mainnet cannot
install the oracle record. The full dom-chain regression passes 194/194 tests,
the feature suite passes 9/9, and formatting plus clippy -D warnings pass. See
docs/DOM-CHECKPOINT-POC-2026-10-17.txt and
results/dom-checkpoint-poc-2026-10-16. This proves the local reorganization
barrier only. It does not implement a network consensus rule, native USDOM,
Ethereum evidence verification or a private burn proof, so real-funds and
mainnet readiness remain false.

Checkpoint v2 handoff and rollback protection (2026-10-17)
The isolated feature now also carries the complete bounded v2 handoff previously
validated between an EVM checkpoint event and Rust. Its 417-byte record binds DOM
state to asserted Ethereum execution, receipt, state, Beacon, registry code,
configuration and domain identities, and recomputes the Solidity-compatible event
digest. Runtime deletion stops every guarded chain-ingress route. Restart requires
an independently supplied regtest floor, so deleting or restoring an older
checkpoint database fails closed before repair or pruning. The focused suite
passes 24/24 tests; the decoder example builds; formatting and clippy with warnings
as errors pass. See docs/DOM-CHECKPOINT-HANDOFF-2026-10-17.txt. The external floor
and all Ethereum fields are still TEST ORACLE input. No light-client result is
connected to ChainState, and no network consensus activation exists.

Consensus dependency guard (2026-10-17)
The existing operational EVM adapters trust an RPC endpoint's `finalized` view
and are therefore excluded from the USDOM checkpoint dependency graph. Run
python3 scripts/check-checkpoint-boundary.py to verify that the experimental
dom-chain feature remains opt-in, regtest-only and free of RPC/EVM authority.
See docs/CHECKPOINT-CONSENSUS-BOUNDARY-2026-10-17.txt. This guard prevents an
unsafe shortcut; it does not implement authenticated Ethereum finality.

Repository-local Ethereum verifier lab (2026-10-17)
The authenticated finality/receipt/state experiment is now copied into
../usdom-ethereum-finality with the exact clean Helios 0.12.0 source at commit
2af9b41887e069144ee56cd710f3ddca195473f8 vendored under that lab. Its isolated
offline run passes 39 functional tests plus four compile-fail API-isolation doc
tests. It is not a workspace member or a dom-chain dependency. Connecting its
opaque verified results to the checkpoint state transition remains pending.

Native USDOM state and request replay hardening (2026-10-17)
The new dom-usdom-state crate provides the separate asset's canonical note,
nullifier, deposit, burn, supply, Ethereum-anchor and exact-undo state. dom-store
can persist its deltas and undo atomically with a block or reorganization. Burn
records now commit a globally unique requestId as well as burnId, matching the
two replay domains enforced by the Ethereum reserve. Nine state tests, one
compile-fail API test and the LMDB restart/reorg integration pass. The current
Solidity campaign passes 94/94 tests in the default and deep profiles; all three
deep invariants complete 131,072 calls without an unexpected revert. Seven fork
tests pass at finalized Ethereum block 26210509 with no public transaction.
See docs/NATIVE-USDOM-STATE-ETAPA24-2026-10-17.txt,
docs/NATIVE-USDOM-STATE-ETAPA25-2026-10-17.txt and the matching result folders.
The production privacy verifier and DOM header commitment still do not exist,
so the mainnet constructor gate remains closed and real-funds readiness is false.

Canonical native burn intent (2026-10-17)
BurnRecord now commits the exact Ethereum payout obligation before block and
finality fields exist: burnId, requestId, recipient, amount, DOM domain, expiry,
Ethereum chain ID and reserve address. Rust state application and persistence,
the Solidity reserve and the JavaScript SDK reproduce the same ABI/Keccak
commitment and reject substitution. Stage 26 passes 10 native-state tests plus
one compile-fail test, the full dom-store suite, 95/95 default and deep Solidity
tests, 33/33 Node tests and 7/7 local mainnet-fork tests. See
docs/NATIVE-BURN-INTENT-ETAPA26-2026-10-17.txt. This closes field binding only;
the production proof, native header commitment and mainnet gates remain pending.

Versioned native block-transition commitment (2026-10-17)
The native core now commits every verified transition, its ordered indexed batch
root and the exact previous/new USDOM state roots into one versioned value meant
for a future DOM header. Batch application is atomic, empty batches are
canonical, and bounded v2 rollback bytes are accepted only with the matching
authenticated receipt. Thirteen state tests, one compile-fail API test, the LMDB
restart/reorg integration and the full dom-store suite pass. See
docs/NATIVE-BLOCK-ENVELOPE-ETAPA27-2026-10-17.txt. The live BlockHeader and Block
formats are intentionally unchanged until a reviewed proof envelope, block v4
activation rule and full validation path exist; no consensus activation occurred.

Immutable native bridge identity (2026-10-17)
Native state now commits and enforces the DOM domain, Ethereum Beacon genesis
validators root, EVM chain ID and reserve address. Issuance from another Beacon
chain and burns targeting another chain or reserve fail before state mutation,
including internally consistent foreign burn commitments. Batch rollback now
requires the authenticated header commitment directly and never trusts persisted
undo bytes to authorize themselves. See
docs/NATIVE-BRIDGE-IDENTITY-ETAPA28-2026-10-17.txt. Production configuration,
BlockHeader v4 integration and the private verifier remain pending.

Ethereum-anchored native burn deadlines (2026-10-17)
EthereumAnchor now commits the finalized execution payload timestamp. Native burn
admission uses the later DOM/Ethereum time for its minimum, never lets DOM time
extend the reserve's seven-day maximum, and rejects stale Ethereum anchors under
a committed overflow-safe timing policy. Fourteen state tests, the compile-fail
API guard, LMDB restart/reorg integration, clippy, release build and all-target
workspace check pass. See docs/NATIVE-BURN-DEADLINE-ETAPA29-2026-10-17.txt. An
independent checkpoint transition, BlockHeader v4, private verifier and production
parameters remain pending; mainnet and real-funds readiness remain false.

Authenticated Ethereum timestamp handoff (2026-10-17)
The finality verifier's opaque FinalizedExecution now preserves the execution
payload timestamp and binds it in the canonical replay transcript. Opaque
VerifiedCheckpoint exposes that authenticated identity without allowing callers
to construct it. The existing 417-byte v2 DOM handoff remains byte-identical and
therefore does not independently carry the timestamp. The verifier suite passes
44 functional and 5 compile-fail tests; the verified DOM handoff/barrier passes
26 tests. See docs/ETHEREUM-TIMESTAMP-HANDOFF-ETAPA30-2026-10-17.txt. Native
checkpoint application and consensus activation remain pending.

Native authenticated checkpoint transition (2026-10-17)
Native USDOM can now advance its Ethereum finality/time anchor without issuing
currency. The opaque adapter binds the verified light-client capability to the
immutable bridge identity; replay, same-slot conflict and height/timestamp
regression fail before mutation. Historical deposits cannot lower the independent
anchor. Canonical persistence and LMDB rollback cover checkpoint-only states.
See docs/NATIVE-CHECKPOINT-TRANSITION-ETAPA31-2026-10-17.txt. Block v4/header
integration, a real registry witness, private proofs and production activation
remain pending.

Native USDOM header/PoW binding (2026-10-17)
The reserved block-v4 consensus primitive now binds the existing body-bound
range-proof root to the native ordered-batch header commitment under a separate
domain. The resulting value occupies the existing rangeproof_root field and is
therefore covered by the frozen header serialization and PoW preimage. An
explicit validator accepts this semantic only on Regtest; every normal network
schedule still rejects v4. Tests cover substitution, missing values, timestamp,
network and PoW-preimage sensitivity. See
docs/NATIVE-HEADER-BINDING-ETAPA32-2026-10-17.txt. The proof envelope and all live
ChainState/mining/P2P/IBD/reorg integration remain pending, so public activation,
mainnet readiness and real-funds readiness remain false.

Opaque native state-to-v4 candidate adapter (2026-10-17)
The opt-in native-usdom-v4-poc adapter no longer accepts a caller-selected batch
hash. It applies opaque proof-verified transitions to a state clone, derives the
ordered batch receipt and uses that exact commitment to body-validate the reserved
Regtest v4 candidate. The returned non-cloneable capability keeps the candidate
state, receipt and undo together; substitutions fail without mutating the input.
Its name and API explicitly exclude parent, timing, target, accumulated-difficulty
and PoW checks, which remain future ChainState work. See
docs/NATIVE-V4-STATE-ADAPTER-ETAPA33-2026-10-17.txt. No peer proof envelope,
persistence, public activation or real-funds readiness exists.

Canonical native proof envelope and committed Ethereum policy (2026-10-17)
The Regtest-only v4 path now decodes one canonical bounded proof envelope. It
recognizes all four native transition kinds but activates only the real Ethereum
checkpoint-witness verifier; issuance, transfer and burn fail closed until their
reviewed proof systems exist. Envelope size, entry size, count, exact framing and
canonical roundtrip are enforced. Ethereum max_current_slot is derived from the
DOM header time. The full immutable checkpoint policy is hashed, carried inside
the opaque verified capability and committed by BridgeIdentity into native state
and persistence, closing direct-converter and local-misconfiguration bypasses.
See docs/NATIVE-PROOF-ENVELOPE-ETAPA34-2026-10-17.txt. The envelope is not yet in
Block/P2P/ChainState and no positive real registry witness exists; mainnet and
real-funds readiness remain false.

Header-authenticated native history projection (2026-10-17)
Verified batches now persist bounded UDPRJ001 public commitment preimages in
USDBAT03. Reloading rehashes every field, reconstructs the ordered transition
root and requires the resulting batch commitment to reproduce the exact native
binding in the canonical DOM header. Private sidecar payloads are returned only
after their nullifiers, output commitments and encrypted-memo scalar match the
header-authenticated projection. See
docs/AUTHENTICATED-HISTORY-PROJECTION-ETAPA81-2026-10-17.txt. Paged RPC delivery,
trusted-tip ancestry validation and atomic wallet rescan application remain
pending; mainnet and real-funds readiness remain false.

Capability-filtered native-v4 peer fan-out (2026-10-17)
Canonical native package relays now carry exact accepted bytes plus an optional
origin connection. Each peer task sends command 0x0d only on its own mutually
authorized v4 session and skips the source connection. The sender is private,
duplicates do not republish, and channel lag closes locally instead of silently
continuing across a missing package. See
docs/NATIVE-P2P-FANOUT-ETAPA48-2026-10-17.txt. Native IBD, mining, production
proofs and activation remain pending; mainnet and real-funds readiness remain
false.

Contextual native-v4 ChainState direct connection (2026-10-17)
An opt-in Regtest-only ChainState entry now restores and compares canonical
native state, validates direct parent/height, MTP, future time, branch-aware PoW,
ASERT target, accumulated difficulty, fork choice, body, UTXOs and kernel replay,
then commits the block and USDOM batch in one LMDB transaction. The ordinary
connect_block schedule still rejects v4. Exact duplicates are idempotent only
when persisted package bytes match. See
docs/NATIVE-CHAINSTATE-DIRECT-ETAPA37-2026-10-17.txt. Side branches/reorg, P2P,
IBD, mining and public activation remain pending; mainnet and real-funds
readiness remain false.

Atomic side-branch sidecar retention (2026-10-17)
DomStore now has an immutable block_sidecars relation. A non-canonical header,
ordinary body and extension sidecar are retained in one NO_OVERWRITE LMDB
transaction without touching canonical pointers or state, survive reopen, and
are pruned together. Empty, oversized and colliding sidecars fail without
partial writes. Batch undo can derive the commitment that a future reorg must
independently bind to the PoW-authenticated header. See
docs/NATIVE-SIDECAR-STORAGE-ETAPA38-2026-10-17.txt. ChainState branch replay,
promotion, P2P/IBD and mining remain pending; mainnet and real-funds readiness
remain false.

Authenticated native branch rewind and replay (2026-10-17)
The Regtest-only ChainState path now reconstructs a native USDOM state at a
common ancestor by binding every persisted undo back to its PoW-authenticated
header. It then replays every canonical package and immutable proof sidecar in a
candidate branch before atomically retaining the next side block. Tests cover a
two-block side branch and corrupted undo rejection while proving the canonical
tip and state remain unchanged. See
docs/NATIVE-BRANCH-REPLAY-ETAPA39-2026-10-17.txt. Atomic branch promotion and
reorg, P2P/IBD/mining transport, production proofs and public activation remain
pending; mainnet and real-funds readiness remain false.

Atomic native branch promotion and reorg (2026-10-17)
The opt-in Regtest path can now promote a fully replayed native-v4 side branch.
It derives the final USDOM delta from the old canonical tip to the promoted
state, applies height pointers, UTXOs, kernels, native state, undos and old-branch
sidecars in one LMDB transaction, and updates memory only after commit. Directed
sidecar corruption and sidecar substitution leave tip and state unchanged. See
docs/NATIVE-ATOMIC-REORG-ETAPA40-2026-10-17.txt. Live P2P/IBD/mining transport,
automatic ingress selection, production proofs and public activation remain
pending; mainnet and real-funds readiness remain false.

Unified native-v4 package ingress (2026-10-17)
ChainState now has one Regtest-only package ingress that verifies caller state
even for duplicates, routes direct extensions, validates and retains side
branches, and invokes atomic promotion only when ordinary DOM fork choice
selects the candidate. Exact persisted package bytes govern duplicate handling.
See docs/NATIVE-UNIFIED-INGRESS-ETAPA41-2026-10-17.txt. Node/P2P negotiation,
IBD, mining, orphan/future queues, snapshots, production proofs and activation
remain pending; mainnet and real-funds readiness remain false.

Authenticated restart reorg-window audit (2026-10-17)
The native-v4 persistence layer can now audit every canonical package and undo
needed by the maximum reorganization window before traffic is accepted. Each
undo is rebound to its PoW-authenticated header, canonical height index and
current reconstructed state. Reaching the non-v4 activation parent requires the
exact empty bridge state. See
docs/NATIVE-RESTART-AUDIT-ETAPA42-2026-10-17.txt. Node startup integration,
P2P/IBD/mining transport, snapshots, production proofs and activation remain
pending; mainnet and real-funds readiness remain false.

Immutable checkpoint policy and restored runtime (2026-10-17)
StaticCheckpointTrustPolicy discards caller-provided slot ceilings and lets the
native adapter materialize only the value derived from the containing DOM block
timestamp. NativeUsdomV4Runtime binds this policy to BridgeIdentity, restores
the exact canonical state and audits the reorg window before exposing unified
ingress. The binding is checked even for empty proof envelopes. See
docs/NATIVE-IMMUTABLE-RUNTIME-ETAPA43-2026-10-17.txt. DomNode configuration and
negotiated transport, IBD/mining, production proofs and activation remain
pending; mainnet and real-funds readiness remain false.

Feature-gated native-v4 wire package (2026-10-17)
dom-wire now has an opt-in Regtest codec and distinct command for the exact
canonical native-v4 package. Its tagged framing is nonempty, length-bounded,
overflow-safe and rejects truncation, trailing bytes and noncanonical encoding.
The default build has neither the command nor its larger framing allowance, so
public protocol behavior remains unchanged. See
docs/NATIVE-WIRE-PACKAGE-ETAPA44-2026-10-17.txt. Node capability negotiation,
handler/relay/IBD, mining, production proofs and activation remain pending;
mainnet and real-funds readiness remain false.

Native-v4 runtime queue observability (2026-10-17)
The Regtest POC now exports aggregate package/byte gauges and pressure counters
for exact native future and orphan queues without exposing hashes, peers or
private transfer data. Nine isolated Prometheus rules cover high/critical
capacity, rejection, eviction, expiration and stuck work; an operator runbook
preserves evidence and makes clear that alerts have no production pause
authority. See docs/NATIVE-RUNTIME-QUEUE-OPERATIONS-ETAPA51-2026-10-17.txt and
monitoring/native-usdom-v4-queue-alerts.yml. Promtool validation, live alert
drills, mining, snapshots, production proofs and activation remain pending;
mainnet and real-funds readiness remain false.

Proof-reserve emergency queue generation (2026-10-17)
The proof-authorized reserve now assigns every queued withdrawal to an explicit
generation. The first emergency pause invalidates the complete active queue in
constant time, resets its collateral reservations and prevents every prior
entry from executing after resume. Reviewed proofs may be queued again without
letting an old evidence entry erase a replacement request reservation. Execution
also rechecks the pinned verifier code and configuration immediately before the
payout. See docs/PROOF-RESERVE-QUEUE-EPOCH-ETAPA54-2026-10-17.txt. The production
verifier pins remain zero, so Ethereum mainnet and real-funds readiness remain
false.

Generation-bound proof-reserve pause (2026-10-17)
Authorized automation can now call pauseQueueEpoch with the queue generation it
actually inspected. A delayed transaction for an older generation reverts
before it can pause or invalidate a reviewed replacement queue, while the
unbound pause remains available for a deliberate manual emergency. See
docs/PROOF-RESERVE-BOUND-PAUSE-ETAPA55-2026-10-17.txt. No production watcher or
verifier is enabled; mainnet and real-funds readiness remain false.

Canonical native burn-state prover witness (2026-10-17)
The native state can now export a bounded USDBRN03 witness that connects one
public burn obligation through its ordered Merkle path to the exact composite
USDOM state-root decomposition. The codec rejects truncation, trailing bytes,
surplus path nodes and inconsistent bridge, timing, monetary or intent fields.
It exposes no note openings or transfer history. See
docs/NATIVE-BURN-STATE-WITNESS-ETAPA56-2026-10-17.txt. This is read-only prover
input: it does not prove the DOM header, consensus, fork choice or additional
finality, and no Ethereum verifier exists yet. Mainnet and real-funds readiness
remain false.

Canonical block-bound native burn prover input (2026-10-17)
The schedule-bound exporter binds USDBRN03 to the exact canonical v4 block
package and authenticated batch undo in a bounded UDBBLK02 transport. The
transport carries the complete activation schedule: network, chain ID, first
v4 height and empty bridge-state root. Verification recomputes the header
identifier, full scheduled block/body validation, transition count, post-state
root, timestamp, PMMR roots and the USDOM batch binding carried by
rangeproof_root. Export first restores the exact tip and audits the retained
reorganization window. See docs/NATIVE-BURN-BLOCK-BINDING-ETAPA57-2026-10-17.txt
and docs/BURN-PROVER-PORTABLE-SCHEDULE-ETAPA129-2026-10-18.txt. The block
identifier still needs an independently verified DOM consensus, fork-choice
and additional finality proof. Mainnet and real-funds readiness remain false.

Verified Ethereum checkpoint to native burn binding (2026-10-17)
An opaque result from the BLS/SSZ, execution-ancestry, receipt, code and storage
verifier can now be composed with UDBBLK02 only when the authenticated event
names the same DOM height, block, USDOM state root, network, bridge domain,
Ethereum chain/genesis and immutable checkpoint policy. The result retains the
event locator and newer authenticated Ethereum finality head. See
docs/NATIVE-BURN-ETHEREUM-CHECKPOINT-ETAPA58-2026-10-17.txt. This composition
does not yet install the checkpoint atomically into DOM fork choice, and the
registry/proving system is not deployed. Mainnet and real-funds readiness
remain false.

Verified native checkpoint fork barrier (2026-10-17)
The combined Regtest feature now installs a checkpoint only after the opaque
Ethereum result matches an exact canonical persisted burn package. Native direct
connection revalidates the floor, native branch promotion rejects an ancestor
before the checkpoint prior to mutation, and restart requires the independently
retained opaque capability plus its configured policy hash. See
docs/NATIVE-CHECKPOINT-FORK-BARRIER-ETAPA59-2026-10-17.txt. Evidence carriage is
still out of band and therefore not a production network consensus rule;
mainnet and real-funds readiness remain false.

Consensus-carried native checkpoint floor (2026-10-17)
The authenticated Ethereum checkpoint capability now remains attached to its
exact native-v4 carrier candidate. ChainState independently reconstructs the
asserted ancestral USDOM state and writes the monotonic floor in the same LMDB
transaction as the carrier block. Direct extensions, promoted side branches,
restart and the v2 snapshot manifest all derive the same floor; a fork cannot
gain checkpoint authority before atomic promotion, and the floor is not erased
when a later permitted reorganization disconnects its carrier. See
docs/NATIVE-CHECKPOINT-CONSENSUS-CARRIAGE-ETAPA60-2026-10-17.txt. This remains
Regtest-only; production proof verifiers, activation, registry deployment,
independent audits and operational validation are pending. Mainnet and
real-funds readiness remain false.

Canonical empty native-v4 Regtest mining (2026-10-17)
An explicitly restored native runtime now derives an empty-batch commitment on
a cloned state, binds it into the PMMR root before RandomX and submits the exact
mined v4 package through shared atomic ingress. Tip races cancel stale work;
accepted bytes persist unchanged, use only the capability-filtered native relay
and survive audited restart. The ordinary miner path remains unchanged when no
native runtime exists. See docs/NATIVE-MINING-ETAPA52-2026-10-17.txt. The miner
cannot include monetary proofs, and production activation, snapshots, proof
verifiers, wallet integration and independent audits remain pending; mainnet
and real-funds readiness remain false.

Audited native-v4 snapshot manifest (2026-10-17)
A compact UDSNAP01 manifest now binds the Regtest DOM tip, height, recomputed
native state and every exact package/undo commitment required by the current
reorg window. Export repeats the full startup audit; verification re-exports
from the supplied store and requires canonical equality. Parsing is bounded and
rejects truncation, trailing data, discontinuity and substituted commitments.
The mechanism is deliberately read-only and provides no snapshot import
authority. See docs/NATIVE-SNAPSHOT-MANIFEST-ETAPA53-2026-10-17.txt. A complete
DOM snapshot, atomic import, production proofs and activation remain pending;
mainnet and real-funds readiness remain false.

Restored native-v4 DomNode runtime (2026-10-17)
dom-node now has explicit Regtest-only constructors that restore and audit the
native runtime from an already activated database before sharing ChainState.
The local ingress decodes exact wire framing, serializes chain/runtime access,
uses unified atomic ingress and reconciles mempool/relay only for canonical tip
changes. Ordinary constructors remain unchanged, unactivated databases fail
closed, and live peers are rejected until a capability is negotiated. See
docs/NATIVE-NODE-RUNTIME-ETAPA45-2026-10-17.txt. Versioned Hello negotiation,
P2P handler/relay, IBD/mining, production proofs and activation remain pending;
mainnet and real-funds readiness remain false.

Authenticated native-v4 capability negotiation (2026-10-17)
The opt-in wire build adds a Noise v4 prologue and an exact Hello-v4 capability
bitmap while the default build remains on v3/v2. Only a node with a restored
native runtime leads with v4; compile-time support alone stays on public v3.
Native authority requires v4 plus the capability bit in both authenticated
Hello messages, and fallback clears that authority. Hello versions now require
their exact shapes, closing cross-version length ambiguity. See
docs/NATIVE-CAPABILITY-NEGOTIATION-ETAPA46-2026-10-17.txt. The live handler,
relay filtering, IBD/mining, production proofs and activation remain pending;
mainnet and real-funds readiness remain false.

Canonical native block-v4 package (2026-10-17)
The Regtest-only adapter now accepts a single canonical package containing the
ordinary DOM block and its proof envelope. Exact framing, version, component
lengths, canonical roundtrip and the existing combined 16-MiB block ceiling are
enforced before proof work. The former public split-input verifier is closed.
The opaque verified capability now binds both the canonical DOM block identifier
and a tagged commitment over every package byte, preventing future persistence
from pairing a verified state with another block or witness encoding. See
docs/NATIVE-BLOCK-PACKAGE-ETAPA35-2026-10-17.txt. ChainState, P2P, IBD, mining,
reorg and proof-cost integration remain pending; mainnet and real-funds
readiness remain false.

Atomic native-v4 persistence handoff (2026-10-17)
The verified package capability now derives a bounded consensus-state batch for
the real LMDB atomic block boundary. State delta, undo, exact proof-envelope
chunks and a chain-tip/state/package marker commit together. Restart restoration
requires bridge identity, canonical tip, state root and reconstructed package to
agree; corruption or substitution fails closed. Activation accepts only the
canonical empty state tied to a nonzero block. See
docs/NATIVE-ATOMIC-PERSISTENCE-ETAPA36-2026-10-17.txt. Live ChainState contextual
validation, side branches/reorg, P2P, IBD and mining remain pending; mainnet and
real-funds readiness remain false.

Authenticated native-v4 P2P ingress (2026-10-17)
The opt-in Regtest node now carries the authenticated bilateral v4 capability
into message_loop and accepts command 0x0d only for an authorized session. Local
and P2P injection share exact framing, canonical package parsing, chain-before-
runtime lock order and atomic consensus ingress. Canonical changes reconcile the
mempool and wallet, refresh metrics and publish the unchanged bytes locally;
invalid packages do not mutate the tip or relay. See
docs/NATIVE-P2P-INGRESS-ETAPA47-2026-10-17.txt. Capability-filtered peer fan-out,
IBD/mining, production proofs and activation remain pending; mainnet and
real-funds readiness remain false.

Capability-filtered native-v4 P2P fan-out (2026-10-17)
Canonical native packages now fan out only to authenticated bilateral v4
sessions, preserve exact bytes and skip the connection that supplied the
package. The relay sender stays private, duplicates do not republish, and lag
closes the affected local session without penalizing its peer. See
docs/NATIVE-P2P-FANOUT-ETAPA48-2026-10-17.txt. IBD, native orphan/future queues,
mining, production proofs and activation remain pending; mainnet and real-funds
readiness remain false.

Authenticated native-v4 headers-first IBD (2026-10-17)
Negotiated Regtest peers can now recover exact persisted native packages through
GetBlockData. A separate explicit v4 header validator preserves normal v3 rules,
fresh pages retain linear batch validation, and package bodies enter through the
same atomic ingress used by live relay. A two-node loopback test covers Noise v4,
bilateral Hello capability, Headers, GetBlockData and convergence to the same
tip. See docs/NATIVE-IBD-ETAPA49-2026-10-17.txt. Native orphan/future queues,
mining, snapshots, production proofs and activation remain pending; mainnet and
real-funds readiness remain false.

Bounded exact native-v4 runtime queues (2026-10-17)
Authenticated Regtest peers now retain child-before-parent and future-timestamp
packages with their exact proof envelope and relay origin. Independent bounded
orphan/future queues replay deterministically through atomic ingress, request
missing parents without closing the source session and shut down under the task
supervisor. Async heap boundaries eliminate a default Tokio stack overflow, and
queue readiness now follows each network's actual timestamp acceptance limit.
See docs/NATIVE-RUNTIME-QUEUES-ETAPA50-2026-10-17.txt. Mining, snapshots,
production proof witnesses, wallet integration and activation remain pending;
mainnet and real-funds readiness remain false.

Native-v4 runtime queue observability (2026-10-17)
The Regtest POC now exports aggregate package/byte gauges and pressure counters
for exact native future and orphan queues without exposing hashes, peers or
private transfer data. Nine isolated Prometheus rules cover high/critical
capacity, rejection, eviction, expiration and stuck work; an operator runbook
preserves evidence and makes clear that alerts have no production pause
authority. See docs/NATIVE-RUNTIME-QUEUE-OPERATIONS-ETAPA51-2026-10-17.txt and
monitoring/native-usdom-v4-queue-alerts.yml. Promtool validation, live alert
drills, mining, snapshots, production proofs and activation remain pending;
mainnet and real-funds readiness remain false.

Issuerless native deposit issuance (2026-10-17)
UDOMDPW1 now replays a bounded Ethereum light-client transcript plus receipt,
execution-ancestry, reserve-account and runtime-code proofs under a consensus-
committed deposit policy. Native issuance derives the initial note exactly from
the authenticated occurrence, amount and receiver commitment; no issuer key or
operator quorum can select another mint. The policy is committed in bridge and
state roots and required across direct ingress, side branches, reorgs, restart
and snapshots. Incompatible experimental formats moved to usdom/v2, USDBRN02
and UDSNAP01 version 3. See docs/NATIVE-ISSUANCE-DEPOSIT-WITNESS-ETAPA61-2026-10-17.txt.
Private transfer/burn proofs, a real finalized-deposit integration vector,
production activation and independent audits remain pending; mainnet and
real-funds readiness remain false.

Header-bound private memo commitments (2026-10-17)
Native transition and batch/header commitments now use canonical encoding
version 2 and include the proof-authenticated encrypted-memo field element for
every private transfer and burn. The ordered batch root and DOM header reject a historical
sidecar that substitutes wallet-recovery ciphertext while preserving the same
note commitments, nullifiers and monetary effects. Wallet observation
recomputes the field element from the exact payload before scanning it; exact
burns without change commit the canonical zero value. See
docs/HEADER-BOUND-PRIVATE-MEMO-ETAPA80-2026-10-17.txt. The change is deliberately
consensus-incompatible with the unactivated version 1 encoding. Authenticated
remote history transport/rescan, production activation and independent audits
remain pending; mainnet and real-funds readiness remain false.

Ethereum reserve activation-schedule binding (2026-10-18)
The proof reserve now fixes the nonzero UDACTV01 activation-schedule
commitment as an immutable constructor value. The same commitment is included
in the reserve identity, deployment configuration hash and every finalized-burn
statement, and the finalized-block preflight compares the live getter with the
signed release evidence. This binds a withdrawal proof to the exact DOM network
magic, chain ID, first v4 height and empty bridge-state identity carried by
UDBBLK02. See
docs/RESERVE-ACTIVATION-SCHEDULE-BINDING-ETAPA130-2026-10-18.txt. The production
schedule, finalized-burn verifier and finality rule remain unratified; mainnet
and real-funds readiness remain false.

Canonical finalized-burn statement handoff (2026-10-18)
The native checkpoint composition now derives the exact Solidity ABI statement
consumed by the proof reserve and rejects bridge, obligation or activation
schedule substitution. The formerly ambiguous finalityEpoch field is explicitly
finalityBeaconSlot across Rust, Solidity and JavaScript, with one frozen
cross-language type hash and statement vector. See
docs/FINALIZED-BURN-STATEMENT-HANDOFF-ETAPA131-2026-10-18.txt. This closes the
prover/reserve encoding boundary; it does not implement or authorize the
production proof system, activation, mainnet deployment or real funds.

Canonical finalized-burn verifier manifest (2026-10-18)
The release gate no longer accepts verifierConfigHash as an opaque assertion. A
strict canonical manifest commits the exact statement versions, DOM activation
schedule and consensus/state rules, finality rule, proof system, verifying key,
trusted-setup decision, proving program, source manifest, verifier artifact and
proof-size/Beacon-slot policy. The gate binds the canonical file SHA-256 and
recomputed config hash to separate evidence artifacts and the release. See
docs/CANONICAL-VERIFIER-CONFIG-MANIFEST-ETAPA132-2026-10-18.txt. The production
manifest and verifier remain unconfigured, so mainnet and real funds remain
blocked.

Portable finalized-burn proving input (2026-10-18)
UDFINL01 now carries the complete UDBBLK02 native burn input, the exact immutable
checkpoint policy and the raw bounded Ethereum BLS/SSZ/receipt/state witness.
The reference verifier recreates the opaque checkpoint, binds it to the native
burn and derives the exact public Solidity statement without accepting a
host-created checkpoint capability. The proof reserve independently rejects
future and more-than-seven-day-old Beacon slots. See
docs/PORTABLE-FINALIZED-BURN-INPUT-ETAPA133-2026-10-18.txt. A production succinct
guest/circuit, verification key, Solidity verifier and finalized registry event
vector are still absent; mainnet and real funds remain blocked.

Deterministic finalized-burn program boundary (2026-10-18)
The new dom-usdom-finalized-burn-program crate accepts only canonical UDFINL01,
reexecutes the complete native/Ethereum relation and emits exactly the raw
32-byte Solidity statement hash, with no partial output on failure. Verifier
manifest v2 now distinguishes UDBBLK02 input v2, UDFINL01 input v1 and public
output v1. See
docs/DETERMINISTIC-FINALIZED-BURN-PROGRAM-ETAPA134-2026-10-18.txt. The reference
program still has host-only transitive node dependencies and has not been
compiled or proven in a selected zkVM; production readiness remains false.

Proof-authorized immutable checkpoint registry (2026-10-18)
DOMCheckpointRegistry now supplies the exact Ethereum event, runtime identity
and slot-zero configuration relation consumed by the finalized checkpoint
witness. Permissionless submissions must strictly extend the current head and
return the exact acceptance magic from an immutable code/config-pinned
verifier. The only emergency authority is a permanent guardian halt, which can
censor but cannot forge or replace checkpoints. JavaScript/Solidity hashes and
the Rust-authenticated event ABI are checked end to end. See
docs/PROOF-AUTHORIZED-CHECKPOINT-REGISTRY-ETAPA135-2026-10-18.txt. The production
consensus-extension verifier, ratified bootstrap, pinned artifacts, finalized
positive event vector and independent audits remain absent, so mainnet and real
funds remain blocked.

Checkpoint registry release and finalized-state binding (2026-10-18)
The release gate now derives the checkpoint registry runtime and constructor
initcode from a forced source-verified build, recomputes its CREATE address and
full immutable/bootstrap configuration, cross-checks all production source pins,
and requires separately hash-addressed registry, verifier, ratification and
finalized-event evidence. The mainnet preflight independently checks both
creation transactions, live code/config identities, every registry immutable,
the authenticated slot-zero configuration, the exact bootstrap event in the
creation receipt, and an unhalted one-checkpoint cold start at the ratified
bootstrap. See
docs/CHECKPOINT-REGISTRY-RELEASE-BINDING-ETAPA136-2026-10-18.txt. Production
verifier code, ratified values, audits and operator authorization remain absent;
therefore both release modes continue to fail closed and no deployment or funds
are authorized.

Portable finalized-burn inclusion program (2026-10-18)
UDFINL02 replaces the host-bound UDFINL01 composition with a bounded burn-state
inclusion proof against an Ethereum-finalized checkpoint-registry event. The
registry verifier owns the DOM consensus-extension proof; the burn program
authenticates the raw Ethereum witness and binds the exact USDBRN03 obligation,
state root, bridge identity, activation schedule and Solidity statement. Its
normal dependency graph excludes dom-chain, LMDB, RandomX, Tokio and RPC code,
and a locked-graph firewall enforces that boundary. See
docs/PORTABLE-FINALIZED-BURN-INCLUSION-PROGRAM-ETAPA137-2026-10-18.txt. A
positive raw checkpoint vector, production consensus-extension verifier,
selected proof backend, guest build, benchmarks and audits are still absent;
mainnet and real-funds readiness remain false.

Activation-bound checkpoint bootstrap (2026-10-18)
The checkpoint registry now accepts only the canonical empty USDOM state at the
height immediately before native v4 activation. DOM chain ID, first v4 height
and the empty root are immutable, committed in slot zero and cross-checked
against a byte-for-byte UDACTV01/BLAKE2b recomputation in the release gate.
Construction emits a distinct CheckpointBootstrap event; only a successful
consensus-extension proof emits the Checkpoint event accepted by finalized-burn
witnesses. Verifier manifest v4 additionally commits the explicit empty root.
See docs/ACTIVATION-BOUND-CHECKPOINT-BOOTSTRAP-ETAPA138-2026-10-18.txt. The
production checkpoint verifier, positive finalized witness, proof backend and
independent audits remain absent, so mainnet and real funds remain blocked.
Etapa 139 — fronteira pública do verificador de checkpoint (2026-10-18)

UDCPST01 fixa em Rust os 306 bytes públicos e o hash Solidity exato consumido
pelo DOMCheckpointRegistry. O vetor Rust/Solidity/JavaScript é idêntico e a CLI
não emite saída parcial diante de framing, identidade ou extensão inválidos.
O novo manifesto usdom-checkpoint-verifier-config-v1 liga consenso, fork choice,
RandomX/PoW, estado nativo, modelo da testemunha, intervalo máximo de 360 blocos,
backend, chaves e artefatos. O gate de release exige evidência e trusted setup
separados para esse verificador. Isto ainda não implementa a relação privada de
extensão do consenso; mainnet e fundos reais continuam bloqueados. Ver
docs/CHECKPOINT-VERIFIER-PUBLIC-BOUNDARY-ETAPA139-2026-10-18.txt.

Etapa 140 — rodadas de checkpoint selecionadas por trabalho (2026-10-18)

A revisão adversarial encontrou que uma prova de extensão válida não bastava para
escolher a cadeia DOM canônica: o primeiro relayer poderia fixar um side branch
válido de menor trabalho. O registro agora usa alturas fixas, trabalho acumulado,
um sufixo de confirmação, competição determinística durante uma janela Ethereum
e finalização permissionless separada. Somente a finalização emite Checkpoint;
candidatos emitem outro evento e não autorizam resgates. O formato incompatível
foi promovido para UDCPST02/v2, com 442 bytes, e todos os novos parâmetros fazem
parte dos hashes, initcode, release gate e preflight. Ver
docs/WORK-SELECTED-CHECKPOINT-ROUNDS-ETAPA140-2026-10-18.txt. O programa zk de
consenso, artefatos de produção, bootstrap ratificado e auditorias independentes
ainda faltam; mainnet e fundos reais permanecem bloqueados por construção.

Etapa 145 — candidato de estado nativo autenticado versionado (2026-10-18)

StateCommitmentV2 agora vincula os acumuladores de notas, histórico de âncoras,
totais monetários, âncora Ethereum e sete conjuntos esparsos autenticados. Dois
índices adicionais preservam a unicidade da identidade finalizada por altura
de execução e slot Beacon, inclusive quando vários depósitos compartilham o
mesmo checkpoint. UDNSET01 usa caminhos sequenciais canônicos e distingue
inserções de reutilizações exatas. O root v1 não mudou e v2 não está ativado.
Executor stateless completo, migração, backend de prova, parâmetros ratificados
e auditorias independentes ainda bloqueiam mainnet e fundos reais. Ver
docs/VERSIONED-NATIVE-AUTHENTICATED-STATE-ETAPA145-2026-10-18.txt.

Etapa 146 — executor nativo stateless candidato v2 (2026-10-18)

UDNVW001 combina as testemunhas de acumuladores e dos sete conjuntos, sempre
vinculadas ao root anterior autenticado. O executor reproduz emissão,
checkpoint, transferência privada e queima, incluindo contabilidade, âncoras,
prazos e consistência Ethereum, e coincide integralmente com o estado completo.
Lotes ordenados encadeiam cada root intermediário e rejeitam testemunhas ausentes
ou reordenadas. V2 continua inativo; integração do envelope de provas, migração,
backend de produção, parâmetros ratificados e auditorias independentes ainda
bloqueiam mainnet e fundos reais. Ver
docs/NATIVE-V2-STATELESS-EXECUTOR-ETAPA146-2026-10-18.txt.

Etapa 147 — capacidade opaca de bloco candidato v2 (2026-10-18)

Lotes v2 agora usam compromisso de cabeçalho versão 3, com versão de estado 2
explícita. O pacote canônico gera uma capacidade opaca após verificar todas as
provas; as transições permanecem privadas e vinculadas ao bloco e aos bytes do
pacote. Somente a execução com testemunhas autenticadas e a validação do corpo
produzem um candidato V2. Um teste Groth16 real cobre toda a fronteira. Ainda
faltam versionar o statement de checkpoint e a ativação, migrar persistência,
produzir artefatos de prova e concluir auditorias. Ver
docs/OPAQUE-V2-BLOCK-CAPABILITY-ETAPA147-2026-10-18.txt.

Etapa 148 — ativação e checkpoint V2 explicitamente versionados (2026-10-18)

UDACTV02 liga a migração ao mesmo snapshot V1/V2, pai de ativação, rede e
versões de estado/lote. O programa de checkpoint agora executa cada capacidade
opaca com testemunhas nativas e econômicas limitadas. UDCPST04 inclui
explicitamente estado 2 e lote 3; o registro Solidity, o SDK JavaScript e o
manifesto V5 usam a mesma identidade e o vetor congelado `0xaea1…249e`.
Um vetor otimizado recompõe 360 blocos de checkpoint e 30 confirmações com PoW,
coinbases, estado econômico e lotes nativos vazios. Ainda faltam inserir nesse
vetor depósito finalizado, transferência privada, queima e resgate, além da
persistência/migração ratificada, backend de prova, artefatos imutáveis, ensaio
operacional e auditorias independentes. Ver
docs/VERSIONED-V2-CHECKPOINT-ACTIVATION-ETAPA148-2026-10-18.txt.

Etapa 167 — guest RISC Zero reproduzível para UDFINL02 (2026-10-19)

O wrapper dom-usdom-finalized-burn-risc0-guest executa a relação completa do
programa portátil, limita a entrada privada antes da alocação e publica somente
o hash de statement de 32 bytes. RISC Zero 3.0.6 está fixado exatamente. Uma
compilação RV32IM limpa com a imagem oficial Rust 1.97 fixada por digest
reproduziu o ProgramBinary SHA-256 `a7b7c9a1…1b9819` e o ImageID
`7fc186e9…58d51b62`. O ImageID foi conferido pelo builder, por r0vm e pela API
risc0-binfmt. Entradas vazia, acima do limite e malformada abortaram no guest
real sem receipt de sucesso. Ainda faltam testemunha Ethereum positiva,
benchmark do caminho válido, geração/verificação de receipt, verificador EVM,
revisão independente e a prova separada de extensão do consenso. Ver
docs/FINALIZED-BURN-RISC0-GUEST-ETAPA167-2026-10-19.txt.

Etapa 168 — adaptador EVM imutável do receipt RISC Zero (2026-10-19)

DOMFinalizedBurnRiscZeroVerifier liga a ABI da reserva ao verificador Groth16 v3,
fixando chain ID, hash do bytecode, seletor `0x73c457ba`, ImageID do guest e o
schema do journal. A leitura do seletor limita gás e retorno; troca de código,
seletor ou rede, return bomb e seals malformados falham fechados. Oito testes
incluem a fila completa da USDOMProofReserve. A referência mainnet oficial foi
registrada por tag, commit, endereço, seletor e code hash, mas ainda não existe
receipt Groth16 real de uma testemunha Ethereum positiva. O gate de verificação
EVM, deploy e fundos reais continua fechado. Ver
docs/FINALIZED-BURN-RISC0-EVM-ADAPTER-ETAPA168-2026-10-19.txt.
Stage 208 binds wallet history finality to both an opaque Ethereum-verified DOM
checkpoint and the matching consensus checkpoint floor reported by the local
full node. Ordinary authenticated-history RPC remains explicitly non-final.
See docs/VERIFIED-CHECKPOINT-WALLET-HISTORY-FINALITY-ETAPA208-2026-10-20.txt.

