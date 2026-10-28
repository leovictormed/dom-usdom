# Pilot Safe custody and untrusted relayer design

The iPhone OneKey path authorizes only complete Safe EIP-712 transactions. It
must never call `eth_sendTransaction`, and the relayer key must never custody
USDT or hold a governance or guardian role.

For the gate, the Safe owners authorize the exact `execTransaction` payload.
The relayer supplies only a separately signed type-2 outer transaction. Its
create-once envelope fixes chain, EOA, Safe target, calldata hash, Safe hash,
nonce, value zero, gas and fee caps. The executor rejects a relayer equal to
the token, reserve, governance/guardian Safe or any configured Safe owner.
Changing the relayer transaction cannot change the authorized Safe action.

Before a real deposit, custody must move from the operator EOA to a dedicated
deposit Safe. The Safe must execute two independently reviewed EIP-712 actions:

1. `USDT.approve(reserve, amount)` for the exact amount, after proving the
   previous allowance is zero (or first executing a Safe-authorized reset).
2. `reserve.deposit(amount, salt, receivingCommitment)` with the same amount
   and the reviewed commitment, followed by a finalized receipt check and an
   allowance-zero/post-balance check.

The deposit contract must observe the Safe as `msg.sender`/funder. The relayer
only wraps each Safe `execTransaction`, pays bounded ETH gas, has zero USDT
allowance and balance by operational policy, and cannot replace token, reserve,
amount, salt, commitment, Safe nonce or signature quorum. Approve and deposit
must use consecutive create-once Safe plans, separate EIP-712 signatures and
separate finalized receipts; failure after either raw appears is inconclusive
and cannot trigger blind re-signing or replay. This migration is required
before a closed real-funds deposit; the current EOA-funder deposit path remains
blocked for that use.
