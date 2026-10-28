# OneKey Classic 1S migration inventory — ETAPA 2288

Date: 2026-10-28

## Decision and boundary

The mainnet operator hardware is OneKey Classic 1S. Ledger-specific production paths are therefore migration blockers and cannot remain as a production fallback.

`sdk/onekey-ethereum-mainnet.mjs` establishes the first isolated boundary. It accepts an injected OneKey transport exposing only the official Ethereum operations `evmGetAddress`, `evmSignTransaction`, and `evmSignTypedData`. It never receives a mnemonic, private key, passphrase, or software signer. The boundary:

- fixes Ethereum mainnet (`chainId = 1`);
- validates one canonical BIP-44 Ethereum derivation path and one checksummed expected address;
- asks the device to display the address immediately before every signature;
- binds the live `connectId` and `deviceId` to every official SDK call;
- binds transaction signatures to the exact EIP-1559 `unsignedHash`, then reconstructs and validates the raw transaction byte for byte;
- binds typed-data signatures to the exact EIP-712 digest and verifies signer recovery;
- fails closed if any OneKey operation is unavailable and contains no Ledger or software-key fallback.

The EIP-1559 response parser accepts exactly `{v,r,s}`. It requires the SDK's canonical parity string (`0x0` or `0x1`), bounded 32-byte `r` and `s`, and no additional fields before independently composing the Ethereum signature. The currently evaluated SDK 1.2.6 transport is not approved for production because its transitive dependency audit is still under review; the pure boundary therefore does not import or silently select that package.

The transport is injected so the security contract can be exercised offline with a deterministic mock. The later operator correction established that the real device connects through Bluetooth. A pinned official BLE transport and the migration of every caller therefore remain required before a real ceremony; the researched USB path is not a production fallback.

## Directed inventory

A source-only search for explicit Ledger commands, variables, helpers, and tests found 51 material files outside the continuation log:

| Area | Files | Migration implication |
| --- | ---: | --- |
| Production scripts | 21 | Replace address discovery, transaction signing, typed-data signing, probes, and ceremony wording. |
| SDK helpers | 3 | Retire Ledger EIP-1559 preparation/assembly after OneKey callers and independent checkers are in place. |
| Tests | 22 | Preserve each security property while replacing device-specific expectations and adding mocked OneKey failure cases. |
| Configuration | 2 | Replace Ledger readiness/critical-source requirements with pinned OneKey transport and adapter evidence. |
| Operator documentation | 2 | Rewrite the device ceremony and bounded-identity instructions for OneKey Classic 1S. |
| Package command surface | 1 | Remove the Ledger probe command after the OneKey probe exists. |

The production-script inventory includes the main deployment, Safe control deployment and recovery, reserve resume, pilot gate/cancel/expired clear, closed deposit/redemption, phase generation, private burn preparation, release/checkpoint signing, and deployment-identity materialization.

## Test evidence

The offline mock suite proves:

- only the three OneKey Ethereum methods are called;
- address display, derivation path, checksum address, and mainnet chain are exact;
- modified unsigned transaction hashes and modified EIP-712 messages fail closed;
- signatures are canonical and recover to the expected hardware address;
- the adapter contains no legacy signer or secret fallback.

No hardware, USB device, network, RPC, signature ceremony, transmission, deployment, or funds were accessed.
