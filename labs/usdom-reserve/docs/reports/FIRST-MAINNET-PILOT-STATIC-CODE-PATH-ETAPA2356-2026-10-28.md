# First mainnet pilot static code-path audit — ETAPA 2356

This audit inspected the 23 generated operator phases and their current OneKey iPhone, Safe, gas-only relayer, deposit and redemption executors. It did not access a network, hardware wallet, private key or funds.

## Implementation gaps that still require code

1. **Safe deposit accounting observers have no production collector command.** `execute-closed-mainnet-deposit.sh` stops with status 78 while waiting for `safe-deposit-observer-a.json` and `safe-deposit-observer-b.json`. The repository validates these documents and has a bounded pinned RPC client, but no command derives the complete pre/post state, receipts and logs from the two approved RPC origins and installs both observations. This is now the largest remaining local blocker for completing the first real deposit.
2. **The configured Safe custody authority has no correctly ordered phase materializer.** The authority needs the finalized four-Safe baseline, configured release, pilot snapshot, pilot relayer identity and private dual-RPC catalog. The operator phases do not yet snapshot and materialize those inputs after the pilot snapshot exists, nor export the resulting authority to the deposit executor.
3. **The closed DOM node still requires a separately started operator terminal.** The deposit phase contains a manual precondition comment for `run:closed-mainnet-node`; the phase state machine does not start, authenticate, monitor and stop that process itself.
4. **Emergency cancel/expired-clear remain outside the generic status-78 signer cycle.** Their executors create exact relayer envelopes, but recovery still depends on rerunning their individual commands rather than the common phase orchestrator.

## External evidence that commands must collect

- Three distinct OneKey iPhone owner onboarding observations and twelve Safe role/slot EIP-712 custody signatures.
- Five separate encrypted gas-only relayer identities and their non-overlap evidence.
- Four finalized Safe deployments, one for each governance, reserve guardian, checkpoint guardian and USDT custody role.
- WalletConnect EIP-712 responses for pilot authorization, Safe USDT approve/deposit and later redemption/recovery actions.
- Two independent, pinned RPC observations of every publication, canonical receipt, finalized block and post-state.
- The real DOM node issuance, wallet and privacy evidence after the Ethereum deposit is finalized.
- Final operator ratification bound to the exact deposit plan and observed accounting result.

## Findings corrected in this stage

- Removed the impossible dependency cycle where the owner-migration phase demanded the final Safe package before it could collect the twelve signatures needed to approve that package. The mobile orchestrator now exposes separate resumable onboarding and custody-proof scopes. The phase first completes onboarding, derives one prospective package, then collects and independently verifies all twelve signatures against those exact bytes.
- Bound owner identities and custody proofs to one private pilot state directory so later phases consume the artifacts actually produced by the mobile ceremony.
- Removed the null `safe` read from the unconfigured custody template. Pilot-funds authorization now derives its funder from exactly one `usdtCustody` role in the finalized four-Safe baseline.

No legacy Ledger path, placeholder, claim without a phase, or unjournaled broadcast was found in the active first-pilot route. Status 78 remains intentional only where an external signature or observation must be obtained; the first item above lacks its collector and remains blocked.
