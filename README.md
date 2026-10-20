<div align="center">

# DOM Protocol

### Not a store of value. A means of exchange.

**DOM is an independent Mimblewimble Layer 1 secured by CPU-oriented RandomX proof of work.  
Confidential by construction, deterministic by design, and built to circulate.**

![Mainnet](https://img.shields.io/badge/mainnet-live-2ea44f)
![Release](https://img.shields.io/badge/release-v1.0.0-0969da)
![Consensus](https://img.shields.io/badge/consensus-Mimblewimble-8B7DF0)
![PoW](https://img.shields.io/badge/PoW-RandomX-3FB68B)
![License](https://img.shields.io/badge/license-MIT-blue)

[Mainnet Release](https://github.com/sorenplanck/dom-protocol/releases/tag/v1.0.0) ·
[DOM Wallet V3](https://github.com/sorenplanck/dom-wallet-v3/releases) ·
[Website](https://dom-protocol.org) ·
[Whitepaper](WHITEPAPER.md) ·
[Documentation](docs/) ·
[Security](SECURITY.md)

</div>

> [!IMPORTANT]
> The canonical DOM Mainnet launch source is the immutable Git tag
> [`v1.0.0`](https://github.com/sorenplanck/dom-protocol/releases/tag/v1.0.0),
> pointing to commit
> [`6c58b0383c095384cd0150cabf074aa00fb57b17`](https://github.com/sorenplanck/dom-protocol/commit/6c58b0383c095384cd0150cabf074aa00fb57b17).
> Build production Mainnet software from a published release tag, not from an
> arbitrary development branch.

---

## Contents

- [Overview](#overview)
- [Mainnet status](#mainnet-status)
- [Fair launch](#fair-launch)
- [Monetary policy](#monetary-policy)
- [Consensus and cryptography](#consensus-and-cryptography)
- [Network identities](#network-identities)
- [Protocol limits](#protocol-limits)
- [Official software](#official-software)
- [Build from source](#build-from-source)
- [Run a Mainnet node](#run-a-mainnet-node)
- [Systemd deployment](#systemd-deployment)
- [RPC and metrics](#rpc-and-metrics)
- [Solo CPU mining](#solo-cpu-mining)
- [DOM Wallet V3](#dom-wallet-v3)
- [Independent audit](#independent-audit)
- [Security and verification](#security-and-verification)
- [Reproducible builds](#reproducible-builds)
- [Repository layout](#repository-layout)
- [Development and testing](#development-and-testing)
- [Future Layer 2 work](#future-layer-2-work)
- [Contributing](#contributing)
- [Security disclosure](#security-disclosure)
- [Official links](#official-links)
- [License](#license)

---

## Overview

DOM is a permissionless monetary network built around the Mimblewimble
construction. Transaction amounts are hidden inside Pedersen commitments and
proven valid with bounded Bulletproof range proofs. Transaction aggregation and
cut-through reduce redundant historical data while every full node independently
validates consensus, proof of work, signatures, range proofs, supply invariants,
state transitions, and chain selection.

DOM uses RandomX proof of work. The mining algorithm is designed to remain
accessible to general-purpose CPUs rather than depending exclusively on
specialized hardware. Difficulty is adjusted with deterministic integer ASERT
arithmetic.

The implementation follows a fail-closed philosophy:

- missing or unknown network selection is rejected before startup side effects;
- malformed and noncanonical encodings are rejected;
- arithmetic used in consensus paths is checked;
- incomplete or inconsistent persisted state is treated as corruption;
- public protocol identities are bound to fixed genesis values and chain IDs;
- RPC and metrics remain disabled unless explicitly enabled;
- mining on public networks requires a compatible local wallet and otherwise
  remains disabled.

DOM is a protocol, not a custodial service. No protocol component can arbitrarily
mint coins, freeze balances, reverse valid ownership, or allocate coins to the
founder outside the public consensus schedule.

---

## Mainnet status

DOM Mainnet is public and the initial bootstrap node is online.

| Item | Value |
|---|---|
| **Network** | Mainnet |
| **Workspace version** | `0.2.0` |
| **Release branch** | `release/mainnetv2` |
| **Launch release** | `v1.0.0` at `6c58b0383c095384cd0150cabf074aa00fb57b17` |
| **Wire protocol version** | `2` (`WIRE_PROTOCOL_VERSION`, `crates/dom-core/src/constants.rs:321`) |
| **Block version** | `2` below height `12,500`; `3` at and above it — see *Consensus upgrade* |
| **Public DNS seed** | `seed1.dom-protocol.org` |
| **Public P2P endpoint** | `seed1.dom-protocol.org:33369` |
| **Direct IP fallback** | `168.100.9.70:33369` |
| **P2P transport** | TCP with authenticated Noise handshake |
| **Bootstrap-node mining** | Disabled |
| **Bootstrap service** | `dom-mainnet.service` |
| **Public RPC** | Disabled; RPC is not exposed by the seed |

**Launch snapshot — 2026-07-18:** the public bootstrap node started at height
`0` with mining disabled. Height is a live network value and changes after valid
proof-of-work blocks are produced.

The initial seed exists to provide public peer discovery, synchronization,
transaction relay, and block relay. It does not receive a protocol allocation and
does not mine on behalf of the project.

### Consensus upgrade — block version 3

Mainnet consensus requires **block version 3 at and above height `12,500`**.
Below that height, version `2` remains the required version. The rule is a
compile-time constant, not a configuration value:

```text
crates/dom-core/src/constants.rs
  WIRE_PROTOCOL_VERSION        = 3      // P2P handshake; independent of consensus
  BLOCK_VERSION_LEGACY         = 2
  BLOCK_VERSION_V3             = 3
  MAINNET_V3_ACTIVATION_HEIGHT = 12_500
```

**This upgrade has already activated.** Mainnet passed height `12,500` and the
network transitioned without incident; the chain has continued producing blocks
under the v3 rules since. The activation is history, not a pending event.

**What this means for node operators today.** A build that predates the upgrade
cannot follow Mainnet at all: it rejects the v3 blocks that make up the current
chain and cannot synchronize past the activation height. Any node must run a
build containing the v3 rules — there is no configuration that restores
compatibility, because the rule is a compile-time constant.

The wire protocol version is deliberately independent from block-version
consensus: `WIRE_PROTOCOL_VERSION` stays `2` across this upgrade, so peer
handshakes are unaffected. Testnet and Regtest activate v3 at their first
post-genesis block, keeping their frozen v2 genesis identities.

### Mainnet identity

```text
Genesis hash:
182e10af28e7ec072f462e6044f580dc9dd8c866cb78dfc293bbfaee4e9325ce

Chain ID:
f9831fadabc8a4234beab35fbb6327e84581645f33e9f75ed2ea78e8bcf1165b

Genesis timestamp:
1784071429 (2026-07-14T23:23:49Z)

Genesis nonce:
7150

Genesis RandomX digest:
000003bda0b141656e3a086fbb2e018321ed2611c9d5a723bf9b85cce9baf3ab

Genesis inscription:
Not a store of value. A means of exchange.
```

The canonical Mainnet genesis economic body is empty:

```text
Inputs:        0
Outputs:       0
Kernels:       0
Transactions:  0
Issued subsidy: 0 DOM
```

Height `1`, not height `0`, is the first reward-bearing Mainnet block.

---

## Fair launch

DOM launched with public proof of work and without a private monetary
allocation.

```text
Premine:              none
ICO:                  none
Presale:              none
Private round:        none
Public prelaunch mining network: none
Founder allocation:   none
Team allocation:      none
Investor allocation:  none
Foundation reserve:   none
Protocol treasury:    none
Developer tax:        none
Genesis issuance:     0 DOM
Initial distribution: permissionless proof-of-work mining
```

The project does not promise price appreciation, exchange listings, investment
returns, market liquidity, or profitability from mining. DOM is experimental
open-source monetary software and participation carries technical, operational,
cryptographic, and market risk.

---

## Monetary policy

All monetary quantities are represented internally in **noms**.

```text
1 DOM = 100,000,000 noms
```

| Parameter | Consensus value |
|---|---:|
| **Genesis issuance** | `0 DOM` |
| **First reward-bearing height** | `1` |
| **Initial block subsidy** | `33 DOM` (`3,300,000,000 noms`) |
| **Reward epoch interval** | `330,000 blocks` |
| **Reward epochs** | `55` entries, including the terminal zero entry |
| **Epoch transition rule** | `next = floor(previous × 67 / 100)` |
| **Exact maximum issuance** | `3,299,996,676,900,000 noms` |
| **Exact maximum issuance in DOM** | `32,999,966.769 DOM` |
| **Coinbase maturity** | `1,000 blocks` |
| **Target block interval** | `120 seconds` |
| **Ordinary transaction fees in v1.0.0** | `100% to the block miner` |

The exact issuance is slightly below 33 million DOM because Mainnet genesis
issues zero coins and the reward schedule uses deterministic integer arithmetic.
Floating-point arithmetic is forbidden in consensus monetary calculations.

---

## Consensus and cryptography

| Component | Implementation |
|---|---|
| **Ledger construction** | Mimblewimble |
| **Proof of work** | RandomX |
| **Difficulty adjustment** | ASERT, 288-block half-life (`34,560 s`) |
| **Consensus hashing** | Tagged/domain-separated BLAKE2b-256 |
| **Commitments** | Pedersen commitments over secp256k1 |
| **Signatures** | Schnorr over secp256k1 with chain-ID binding |
| **Range proofs** | Fixed final Bulletproof format |
| **Canonical range-proof size** | `739 bytes` |
| **Wallet V3 recovery capsule** | `96 bytes` |
| **Maximum provable value** | `2^52 - 1 noms` |
| **Authenticated transport** | Noise protocol |
| **Transaction relay** | Dandelion++ stem/fluff routing |
| **Chain state** | LMDB-backed canonical state with corruption detection |
| **Accumulated work** | Full-width `U256` total difficulty |

### Determinism requirements

Consensus code avoids dependence on:

- host pointer width or Rust memory layout;
- locale, environment-dependent formatting, or floating point;
- unordered iteration where order affects canonical bytes;
- unchecked network-controlled arithmetic;
- implicit padding or trailing-byte acceptance;
- unknown network fallback behavior.

Canonical serialization uses explicit integer widths, explicit endian rules,
bounded allocations, checked length arithmetic, and trailing-byte rejection.

---

## Network identities

| Parameter | Mainnet | Testnet | Regtest |
|---|---|---|---|
| **Magic** | `0x444F4D31` (`DOM1`) | `0x444F4D54` (`DOMT`) | `0x444F4D52` (`DOMR`) |
| **P2P port** | `33369` | `33370` | `33371` |
| **Default RPC port** | `33372` | `33373` | `33374` |
| **Genesis hash** | `182e10af…4e9325ce` | `2ab5e6c7…5cd65821` | `fdda027e…dee3fe1f` |
| **Chain ID** | `f9831fad…bcf1165b` | `de1168ce…53ff770` | `22384b4c…abd698e1` |

Full Mainnet values are shown in [Mainnet identity](#mainnet-identity). Network
magic and chain ID are enforced during handshake; nodes from different networks
must not peer successfully.

---

## Protocol limits

| Limit | Value |
|---|---:|
| Maximum block weight | `40,000` units |
| Maximum transaction weight | `4,000` units |
| Maximum inputs per transaction | `255` |
| Maximum outputs per transaction | `255` |
| Maximum kernels per transaction | `16` |
| Maximum transactions per block | `5,000` |
| Canonical range-proof bytes | `739` |
| Defensive proof-size bound | `768` bytes |
| Wallet V3 recovery capsule | `96` bytes |
| Maximum output proof envelope | `835` bytes |
| Canonical Wallet V3 TransactionOutput | `872` bytes |
| Maximum serialized block size | `16 MiB` |
| Maximum logical P2P message | `16 MiB + 64 KiB` |
| Maximum headers per message | `2,000` |
| Maximum block hashes per data request | `128` |
| Maximum block locator hashes | `32` |
| Maximum future Mainnet timestamp | `120 seconds` |
| Median-time window | `11 blocks` |

Consensus limits and local relay policy are distinct. Policy may reject an item
that consensus could theoretically accept, but policy must never make an invalid
block valid.

---

## Official software

### DOM Core

- Repository: <https://github.com/sorenplanck/dom-protocol>
- Current release branch: <https://github.com/sorenplanck/dom-protocol/tree/release/mainnetv2>
- Launch release: <https://github.com/sorenplanck/dom-protocol/releases/tag/v1.0.0>
  at `6c58b0383c095384cd0150cabf074aa00fb57b17`

The launch tag `v1.0.0` records the genesis-time build and remains valid as a
historical reference only. It predates the block version 3 consensus upgrade,
which Mainnet has already passed, so it cannot synchronize the current chain.

### DOM Wallet V3

The canonical user-facing wallet is maintained and released separately:

- Repository: <https://github.com/sorenplanck/dom-wallet-v3>
- Releases: <https://github.com/sorenplanck/dom-wallet-v3/releases>

Legacy and internal wallet crates that remain in the Core workspace are not the
canonical end-user download channel. Users should obtain Wallet V3 only from its
official release page.

### Public explorer

The Core repository contains the explorer implementation. The public Mainnet
explorer endpoint will be announced through the official website and release
channels after deployment. An explorer is informational; consensus is determined
by validating nodes.

### Checksums

When compiled binaries are attached to a release, use only the checksums
published with that same official GitHub release. Do not trust unofficial mirrors
or checksums copied into third-party messages.

---

## Build from source

### Requirements

- Git
- Rust `1.75` or newer compatible toolchain
- Cargo
- A C/C++ build toolchain suitable for RandomX dependencies
- Common Linux build packages such as `build-essential`, `clang`, `cmake`, and
  `pkg-config`

Example on Ubuntu or Debian:

```bash
sudo apt update
sudo apt install -y build-essential clang cmake pkg-config git curl

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Build the exact Mainnet release

```bash
git clone https://github.com/sorenplanck/dom-protocol.git
cd dom-protocol
git checkout --detach v1.0.0

# Confirm the exact audited release commit.
test "$(git rev-parse HEAD)" = \
  "6c58b0383c095384cd0150cabf074aa00fb57b17"

cargo build --release --locked -p dom-node -p dom-cli -p dom-explorer
```

Release binaries are written to:

```text
target/release/dom-node
target/release/dom-cli
target/release/dom-explorer
```

---

## Run a Mainnet node

The network must be selected explicitly. A missing, padded, mixed-case, or
unknown `DOM_NETWORK` value fails closed before node initialization.

### Validating and relay-only node

```bash
mkdir -p "$HOME/.local/share/dom/mainnet"

DOM_NETWORK=mainnet \
DOM_SEED_PEERS="seed1.dom-protocol.org:33369" \
DOM_MINE=false \
DOM_DATA_DIR="$HOME/.local/share/dom/mainnet" \
DOM_P2P_LISTEN_ADDR="0.0.0.0:33369" \
DOM_LOG=info \
./target/release/dom-node
```

Direct-IP bootstrap fallback:

```bash
DOM_NETWORK=mainnet \
DOM_SEED_PEERS="168.100.9.70:33369" \
DOM_MINE=false \
DOM_DATA_DIR="$HOME/.local/share/dom/mainnet" \
DOM_P2P_LISTEN_ADDR="0.0.0.0:33369" \
DOM_LOG=info \
./target/release/dom-node
```

### Connectivity checks

```bash
getent ahostsv4 seed1.dom-protocol.org
nc -vz seed1.dom-protocol.org 33369
```

To accept inbound peers, allow TCP port `33369` through the host and provider
firewalls. For example, when using UFW:

```bash
sudo ufw allow 33369/tcp
sudo ufw status
```

An outbound-only node can still validate and synchronize, but publicly reachable
nodes improve network resilience.

### Initial DNS rollout note

During the initial Mainnet rollout, some secondary hardcoded seed hostnames may
not yet resolve. Resolution warnings for inactive secondary seeds are operational
warnings, not consensus failures. Use the verified `seed1.dom-protocol.org:33369`
or direct-IP endpoint above and confirm that at least one peer connection is
established.

---

## Systemd deployment

The following example runs a non-mining Mainnet node as an unprivileged service.
Review paths and hardening settings for your distribution before installation.

```bash
sudo install -m 0755 target/release/dom-node /usr/local/bin/dom-node
sudo useradd --system --home-dir /var/lib/dom-mainnet \
  --shell /usr/sbin/nologin dom 2>/dev/null || true
sudo install -d -o dom -g dom -m 0750 /var/lib/dom-mainnet

sudo tee /etc/systemd/system/dom-mainnet.service >/dev/null <<'UNIT'
[Unit]
Description=DOM Protocol Mainnet Node
After=network-online.target time-sync.target
Wants=network-online.target time-sync.target

[Service]
Type=simple
User=dom
Group=dom
WorkingDirectory=/var/lib/dom-mainnet
ExecStart=/usr/local/bin/dom-node

Environment=DOM_NETWORK=mainnet
Environment=DOM_DATA_DIR=/var/lib/dom-mainnet
Environment=DOM_P2P_LISTEN_ADDR=0.0.0.0:33369
Environment=DOM_SEED_PEERS=seed1.dom-protocol.org:33369
Environment=DOM_MINE=false
Environment=DOM_LOG=info

Restart=always
RestartSec=5
LimitNOFILE=65536

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/dom-mainnet
LockPersonality=true
RestrictRealtime=true

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now dom-mainnet.service
sudo systemctl status dom-mainnet.service --no-pager
```

Follow logs:

```bash
sudo journalctl -u dom-mainnet.service -f
```

Verify the listener:

```bash
sudo ss -lntp | grep 33369
```

---

## RPC and metrics

RPC and metrics are disabled by default.

### Enable loopback RPC

```bash
DOM_NETWORK=mainnet \
DOM_SEED_PEERS="seed1.dom-protocol.org:33369" \
DOM_MINE=false \
DOM_DATA_DIR="$HOME/.local/share/dom/mainnet" \
DOM_P2P_LISTEN_ADDR="0.0.0.0:33369" \
DOM_RPC_LISTEN_ADDR=default \
DOM_LOG=info \
./target/release/dom-node
```

For Mainnet, `default` resolves to:

```text
127.0.0.1:33372
```

The RPC includes sensitive wallet-related operations. Keep it on loopback or a
strictly controlled private network and use bearer authentication. Never expose
RPC directly to the public Internet.

### Enable loopback metrics

Add:

```bash
DOM_METRICS_LISTEN_ADDR=default
```

The default metrics endpoint is:

```text
127.0.0.1:3371
```

Metrics reveal operational and topology information and should not be exposed
publicly without access controls.

---

## Solo CPU mining

The public bootstrap node does **not** mine. Mining is permissionless and can be
started by any participant running the released software.

> [!CAUTION]
> Public-network mining requires a compatible encrypted wallet directory.
> The node opens an existing wallet; it does not silently create a replacement.
> If the wallet is missing, invalid, locked elsewhere, or cannot be decrypted,
> mining stays disabled or fails closed. Back up the wallet recovery material
> before mining.

Example:

```bash
read -rsp "Miner wallet password: " DOM_WALLET_PASSWORD
echo
export DOM_WALLET_PASSWORD

DOM_NETWORK=mainnet \
DOM_SEED_PEERS="seed1.dom-protocol.org:33369" \
DOM_MINE=true \
DOM_MINER_THREADS="$(nproc)" \
DOM_WALLET_PATH="/absolute/path/to/compatible/wallet-directory" \
DOM_DATA_DIR="$HOME/.local/share/dom/mainnet-miner" \
DOM_P2P_LISTEN_ADDR="0.0.0.0:33369" \
DOM_LOG=info \
./target/release/dom-node

unset DOM_WALLET_PASSWORD
```

`DOM_MINER_THREADS` is a local resource setting and does not change consensus.
The implementation clamps the worker count to the supported range.

Do not place a wallet password or recovery phrase in:

- a public shell script;
- Git history;
- screenshots;
- a world-readable environment file;
- a public systemd unit;
- an issue report or support message.

For unattended mining, use a root-readable environment file, systemd credentials,
or a dedicated secret manager and restrict all filesystem permissions.

---

## DOM Wallet V3

DOM Wallet V3 is the official user-facing wallet distribution:

- <https://github.com/sorenplanck/dom-wallet-v3>
- <https://github.com/sorenplanck/dom-wallet-v3/releases>

Wallet security rules:

1. Download only from the official Wallet V3 release page.
2. Verify the release version and published checksums.
3. Record the recovery phrase offline.
4. Never share the recovery phrase or wallet password.
5. Test recovery before storing meaningful funds.
6. Keep independent encrypted backups.
7. Treat unsolicited support messages and wallet mirrors as hostile.

DOM Core and DOM Wallet V3 are separate release lines. A Core tag does not
implicitly publish or update the wallet, and a Wallet V3 release does not alter
Mainnet consensus.

---

## Independent audit

A distribution built from this repository — `dom-v2-0.2.0`, packaging Core
executables together with the DOM Wallet V3 shell — completed an independent
audit in August 2026. The audit is documented here because its results are
useful to anyone verifying this software, and because two of its findings
changed the verification instructions above.

**This distribution is not the software currently serving Mainnet.** It is an
audited candidate. The live network runs the release branch identified under
*Mainnet status*. Nothing in this section should be read as a release
announcement.

What the audit established, and what it did not:

- **Byte reproducibility, independently.** Four isolated reviewers, each
  building at a different filesystem path with no network access, produced an
  identical binary from identical sources. Reaching that result required fixing
  a real defect: the original build embedded absolute paths, so it had never
  been reproducible by a third party. The corrected procedure is the one in
  *Reproducible builds*.
- **A complete, public defect record.** The audit closed with findings still
  open, each carrying its measured cause and its destination. They were not
  waived, averaged away, or silently reclassified. Known debts include two
  RustSec advisories in build-reachable dependencies, wallet seed-memory
  hygiene weaker in the audited revision than in current development, and a
  node/wallet compatibility divergence that is dormant in the shipped
  configuration.
- **What it did not cover.** The audit covers exactly the pinned revisions and
  the package it names. It is not a warranty, it does not extend to later
  commits, and it does not replace reading the code.

---

## Security and verification

DOM Core `v1.0.0` was produced after a project-operated final engineering
campaign covering consensus, cryptography, storage, networking, reproducibility,
and formal methods.

The campaign included, among other gates:

- deterministic and adversarial multi-node synchronization;
- Initial Block Download and replay determinism;
- reorganization, fork-choice, tie-break, and persistence tests;
- RandomX seed-transition and persisted-seed validation;
- mempool admission, fee, maturity, duplication, and selection invariants;
- corruption detection and fail-closed storage recovery;
- malformed, truncated, oversized, and adversarial P2P messages;
- property-based testing;
- fuzzing of available Core targets;
- Kani bounded/refinement harnesses;
- selected Miri execution paths;
- supply-chain reachability analysis for Core binaries;
- byte-identical reproducible node, CLI, and explorer builds;
- independent genesis and chain-identity reproduction.

Final project classification:

```text
DOM CORE FINAL CAMPAIGN PASSED
```

This was an internal/project-run engineering verification campaign. It must not
be represented as an independent third-party financial, legal, or security
audit. Passing a large test campaign does not prove that software is free of all
unknown defects.

### Selected fail-closed properties

- unknown network values are rejected before storage or listeners are opened;
- Mainnet genesis identity is fixed and independently reproducible;
- Mainnet genesis issues zero DOM;
- the complete canonical block body is committed and validated;
- invalid or noncanonical persisted records are rejected;
- future timestamp and ASERT arithmetic use explicit checked boundaries;
- unknown-network proof-of-work selection is rejected;
- malformed range-proof points are rejected before native verification;
- RPC-generated bearer-token files are created owner-only;
- public RPC is disabled unless explicitly enabled.

---

## Reproducible builds

The final campaign reproduced the intended Core binaries byte-for-byte using a
fixed source-date epoch and disabled incremental compilation.

Example reproduction environment:

```bash
export SOURCE_DATE_EPOCH=1784071429
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=2

cargo build --release --locked -p dom-node -p dom-cli -p dom-explorer
sha256sum target/release/dom-node \
          target/release/dom-cli \
          target/release/dom-explorer
```

For a meaningful comparison, perform the second build in a clean checkout and a
separate target directory using the same toolchain, lockfile, target triple, and
environment.

**Build at a different absolute path for the comparison to mean anything.**
A build that only reproduces from the same directory proves nothing about
reproducibility: without path remapping, the compiler embeds absolute source,
registry and toolchain paths into the binary, so two builds of identical sources
at two different paths differ byte-for-byte. This was measured, not assumed —
an independent audit reproduced a Core-family binary at three distinct paths and
obtained three distinct binaries from identical sources.

A verification that is independent of where it runs also needs:

```bash
export SOURCE_DATE_EPOCH=1784071429
export CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$PWD=/build \
                  --remap-path-prefix=$HOME/.cargo=/cargo \
                  --remap-path-prefix=$HOME/.rustup=/rustup"
```

Build outside any directory tree that carries an ancestral `.cargo/config.toml`,
and use a clean `HOME`: Cargo discovers configuration from ancestor directories,
so an unrelated file above the checkout can change the output. With these in
place, two builds at two different paths must produce identical bytes; if they
do not, the divergence is a finding, not an expected artifact of the
environment.

---

## Repository layout

The repository is a Rust workspace containing the consensus implementation,
network services, developer tools, legacy/internal wallet components, tests, and
an excluded Tauri desktop application.

```text
dom-protocol/
├── crates/
│   ├── dom-core/                Consensus constants, primitive types, fee policy
│   ├── dom-config/              Network profiles and node configuration
│   ├── dom-serialization/       Canonical bounded encoding and decoding
│   ├── dom-crypto/              Schnorr, Pedersen, range proofs, recovery data
│   ├── dom-pmmr/                Prunable Merkle Mountain Range
│   ├── dom-pow/                 RandomX, ASERT, targets, accumulated work
│   ├── dom-consensus/           Transaction and block validation
│   ├── dom-chain/               Chain state, fork choice, reorg, genesis
│   ├── dom-store/               LMDB persistence and corruption checks
│   ├── dom-mempool/             Admission, validation, selection, reconciliation
│   ├── dom-wire/                Noise transport, codec, handshake, P2P messages
│   ├── dom-node/                Node orchestration, IBD, relay, mining, RPC bridge
│   ├── dom-rpc/                 HTTP RPC server and bearer-token handling
│   ├── dom-cli/                 Core command-line tools
│   ├── dom-explorer/            Explorer service
│   ├── dom-faucet/              Test-network faucet service
│   ├── dom-tx/                  Transaction and recoverable-output construction
│   ├── dom-slate/               Interactive slate protocol
│   ├── dom-test-vectors/        Frozen and adversarial vectors
│   ├── dom-integration-tests/   Multi-node and end-to-end tests
│   ├── dom-wallet*/             Legacy/internal wallet and compatibility crates
│   └── dom-*-runner/            Test and campaign orchestration tools
├── wallet-desktop/              Excluded Tauri desktop application
├── test-vectors/                Canonical genesis and protocol vectors
├── docs/                        Protocol and operator documentation
├── deploy/                      Deployment examples and systemd configuration
├── audit/                       Historical audit and hardening materials
├── WHITEPAPER.md
├── SECURITY.md
└── Cargo.toml
```

The official end-user Wallet V3 is maintained in its own repository and release
channel, as described above.

---

## Development and testing

Install the repository toolchain and run the standard quality gates:

```bash
cargo fmt --all --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Some integration, fuzz, formal-verification, mining, and multi-node campaigns are
resource intensive and must use isolated data directories, target directories,
and ports.

Consensus-sensitive changes require more than ordinary unit tests. Depending on
the affected subsystem, contributors should add:

- deterministic positive and negative vectors;
- property-based invariants;
- differential tests;
- reorg and restart coverage;
- malformed serialization cases;
- fuzz targets;
- Kani or other bounded proofs where practical;
- release-mode regression coverage;
- an explicit impact statement for genesis, chain ID, serialization, PoW,
  monetary policy, wallet recovery formats, and P2P compatibility.

---

## Future Layer 2 work

A future **DOM Layer 2 Settlement Protocol (DL2P)** is being specified as a
post-Mainnet extension so independently developed L2 systems can eventually use
DOM for settlement, custody, proofs, and data availability.

DL2P is **not active in Mainnet v1.0.0**. In particular:

- v1.0.0 does not claim general rollup support;
- no L2 settlement fee split is active in v1.0.0;
- ordinary v1.0.0 transaction fees continue to follow current Core consensus;
- future L2 functionality requires independent RFCs, versioned formats,
  explicit consensus activation, test vectors, formal conservation models,
  Regtest validation, public review, and release-specific testing;
- future work must preserve the frozen v1.0.0 genesis identity and must not
  opportunistically repurpose existing Wallet V3 or V2 consensus fields.

The architectural objective is to evolve DOM into a privacy-oriented proof-of-
work settlement layer without informally changing the released L1 rules.

---

## Contributing

Issues and pull requests are welcome.

- Development changes should target the appropriate development branch.
- `release/mainnet` is the release line and should receive only reviewed release
  documentation or deliberate versioned hotfixes.
- Never rewrite or move a published release tag.
- Every consensus-sensitive change must identify its affected authority and
  include suitable regression evidence.
- Keep code, comments, commits, and technical documentation in English.

Before opening a pull request:

```bash
cargo fmt --all --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

---

## Security disclosure

Do not disclose exploitable vulnerabilities in a public issue before a fix or
mitigation is available.

See [SECURITY.md](SECURITY.md) for the private reporting process.

General technical issues:

<https://github.com/sorenplanck/dom-protocol/issues>

Project contact:

- **Author:** Soren Planck
- **Email:** `sorenplanck@tutamail.com`

---

## Official links

- Website: <https://dom-protocol.org>
- DOM Core: <https://github.com/sorenplanck/dom-protocol>
- Core v1.0.0: <https://github.com/sorenplanck/dom-protocol/releases/tag/v1.0.0>
- Mainnet release branch: <https://github.com/sorenplanck/dom-protocol/tree/release/mainnet>
- DOM Wallet V3: <https://github.com/sorenplanck/dom-wallet-v3>
- Wallet V3 releases: <https://github.com/sorenplanck/dom-wallet-v3/releases>
- Public seed: `seed1.dom-protocol.org:33369`
- Direct seed fallback: `168.100.9.70:33369`
- Issues: <https://github.com/sorenplanck/dom-protocol/issues>

Treat any social-media, Telegram, Discord, wallet, binary mirror, or support
account not linked from the official website or repositories as unofficial.

---

## License

DOM Protocol is released under the [MIT License](LICENSE).

The software is provided "as is", without warranty of any kind. Review the code,
verify release identities and checksums, protect wallet recovery material, and
operate nodes at your own risk.

---

<div align="center">

**No premine. No ICO. No founder allocation. Mainnet from block zero.**

*Not a store of value. A means of exchange.*

</div>

Etapa 141 — contexto autenticado de continuidade dos checkpoints (2026-10-18)

A revisão do futuro provador identificou que bloco, raiz USDOM e trabalho
acumulado não autenticavam a janela histórica de MTP nem as sementes RandomX
anteriores ao checkpoint. UDCCTX01 agora fixa, em 663 bytes, os onze cabeçalhos
recentes e o conjunto derivado de até duas âncoras de semente. O registro mantém
e encadeia o hash desse contexto, e UDCPST03/v3 também vincula o timestamp do
sufixo, que não pode terminar no futuro da Ethereum. Rust, JavaScript e Solidity
compartilham vetores congelados e o manifesto v3 compromete separadamente as
regras do contexto. Ver
docs/AUTHENTICATED-CHECKPOINT-CONTINUATION-ETAPA141-2026-10-18.txt. O programa
zk de extensão do consenso, verificador de produção, bootstrap ratificado e
auditorias independentes ainda faltam; mainnet e fundos reais permanecem
bloqueados por construção.

Stage 142 — authenticated DOM economic state in checkpoints (2026-10-18)

The checkpoint review found that header, PoW and native USDOM validation still
did not authenticate the ordinary DOM UTXO and historical-kernel indexes used
by the live node. UDCCTX02 supersedes UDCCTX01, expands the context to 695 bytes,
and binds a nonzero economic state root. The new
`dom-usdom-checkpoint-program` crate defines deterministic sparse UTXO/kernel
roots, atomic contextual validation, and an explicit host reference that
composes the real DOM header, PoW, body and native USDOM validators through the
full checkpoint and confirmation suffix. The manifest is v4. A bounded
multiproof transport, production proving backend, audited verifier artifacts,
ratified bootstrap and independent audits still block mainnet and real funds.
See
`labs/usdom-reserve/docs/ECONOMIC-CHECKPOINT-STATE-ETAPA142-2026-10-18.txt`.

Stage 143 — bounded checkpoint economic witnesses (2026-10-18)

The checkpoint relation now accepts canonical UDECBW01 witnesses that open and
advance the authenticated UTXO and historical-kernel roots for every serialized
block, without supplying those complete historical sets. UDECPR01 and UDECMP01
freeze the single-path and shared multiproof encodings, and the block witness is
checked against the full-state transition. Native USDOM now has a compressed
UDSMPR01 path and an insertion-bounded in-memory sparse tree, but the native
consensus roots were deliberately left unchanged until persistent atomic
updates, rollback and accumulator-frontier witnesses exist. A proving backend,
complete stateless native relation, production artifacts, ratified operations
and independent audits still block mainnet funds. See
`labs/usdom-reserve/docs/BOUNDED-CHECKPOINT-WITNESSES-ETAPA143-2026-10-18.txt`.

Stage 144 — native sparse caches and note frontiers (2026-10-18)

Native USDOM now maintains five parallel compressed sparse caches across apply,
restore and exact rollback, while leaving the current v1 consensus root
unchanged. UDSMTR01 snapshots the rebuildable cache; PMFRNT01 and UDNTFR01
freeze the bounded PMMR and Poseidon append frontiers; UDAFRT01 opens both note
roots and the retained 256-anchor history without historical notes. The next
incompatible state version must authenticate these sparse roots and compose
their update proofs with the accumulator witness. Until that migration, a real
proving backend, complete vectors and independent audits are complete, mainnet
funds remain blocked. See
`labs/usdom-reserve/docs/NATIVE-STATE-FRONTIERS-ETAPA144-2026-10-18.txt`.

Stage 145 — versioned native authenticated-state candidate (2026-10-18)

The candidate `StateCommitmentV2` now binds the bounded note accumulators,
retained anchors, monetary totals, Ethereum high-water anchor and seven sparse
authenticated sets. The two added sets preserve the full-state rule that one
execution height and Beacon slot cannot acquire conflicting finalized
identities. UDNSET01 advances the sets with canonical sequential paths and
explicit exact-membership no-ops for checkpoints shared by multiple deposits.
The current v1 root is unchanged and v2 is not activated. A complete stateless
executor, activation migration, production proving artifacts, ratified
operations and independent audits still block mainnet and real funds. See
`labs/usdom-reserve/docs/VERSIONED-NATIVE-AUTHENTICATED-STATE-ETAPA145-2026-10-18.txt`.

Stage 146 — candidate-v2 stateless native executor (2026-10-18)

UDNVW001 now composes the bounded accumulator and seven-set witnesses and
requires the exact authenticated previous v2 root. The executor reproduces
issuance, checkpoint, private-transfer and burn state rules, including monetary
limits, Ethereum high-water consistency, retained anchors and deadline policy,
then returns the same complete candidate commitment as full-state execution.
Ordered block batches chain every intermediate root and reject missing or
reordered witnesses. V2 remains inactive; proof-envelope integration,
activation migration, a production proving backend, ratified operations and
independent audits still block mainnet funds. See
`labs/usdom-reserve/docs/NATIVE-V2-STATELESS-EXECUTOR-ETAPA146-2026-10-18.txt`.

Stage 147 — opaque candidate-v2 block capability (2026-10-18)

Candidate-v2 batches now use a distinct version-3 header commitment that
explicitly identifies state version 2. A canonical package is converted into an
opaque proof-verified capability whose transitions remain private and bound to
the exact block and package bytes. Only execution against authenticated native
witnesses followed by block-body validation produces a V2 candidate. A real
Groth16 transfer test covers the complete boundary and rejects missing paths.
Checkpoint-statement versioning, activation migration, proving artifacts,
ratified operations and independent audits still block mainnet funds. See
`labs/usdom-reserve/docs/OPAQUE-V2-BLOCK-CAPABILITY-ETAPA147-2026-10-18.txt`.

Stage 148 — explicitly versioned V2 activation and checkpoint (2026-10-18)

UDACTV02 binds the V1/V2 snapshot roots, activation parent, network and state
and batch versions. The checkpoint program now advances each opaque V2 block
with bounded native and economic witnesses. UDCPST04 explicitly selects state
version 2 and batch version 3; the Solidity registry, JavaScript SDK and V5
verifier manifest share the frozen `0xaea1…249e` vector. An optimized test now
recomputes the full 360+30 PoW/economic extension with empty native batches.
The finalized-deposit/private-transfer/burn flow, ratified persistent migration,
production proof artifacts, operational rehearsal and independent audits still
block mainnet funds. See
`labs/usdom-reserve/docs/VERSIONED-V2-CHECKPOINT-ACTIVATION-ETAPA148-2026-10-18.txt`.

Stage 149 — private lifecycle in the complete checkpoint vector (2026-10-18)

The optimized 360+30 relation now includes a real Groth16 private transfer in
its first extension block and a real Groth16 total burn in its second. Each
proof is reverified through the bridge-committed key and then executed with
bounded V2 native witnesses while all 390 PoW and economic transitions are
recomputed. The input issuance is an explicitly labelled, ratified
pre-activation snapshot, not Ethereum deposit evidence. A finalized reserve
deposit, Ethereum payout, persistent migration/reorg exercises, production
proving artifacts, operations and independent audits still block mainnet
funds. See
`labs/usdom-reserve/docs/PRIVATE-LIFECYCLE-CHECKPOINT-VECTOR-ETAPA149-2026-10-18.txt`.

Stage 150 — persistent V2 activation and lifecycle recovery (2026-10-18)

The nonempty 360+30 vector now restores full native state after both private
blocks, canonically decodes their durable undo, rolls each batch back and
replays it to the identical receipt, bytes and state. The burn height also
checks a competing empty native branch. UDACTV02 now has an atomic persisted
record/marker pair; restart reconstructs the complete V1 snapshot and derives
the ratified V2 root, while partial or substituted records fail closed. Live V2
package ingress and fork-choice integration, real Ethereum deposit/payout,
production proving artifacts, operations and independent audits still block
mainnet funds. See
`labs/usdom-reserve/docs/PERSISTENT-V2-LIFECYCLE-RECOVERY-ETAPA150-2026-10-18.txt`.

Stage 151 — canonical candidate-v2 ingress and restart recovery (2026-10-18)

UDSTV002 now persistently encodes the complete candidate-v2 commitment, while
UDV2W001 carries the bounded ordered state witnesses for one block. ChainState
can validate and atomically commit an exact scheduled V2 direct extension with
its package, witnesses, previous/next states and receipt. Restart restoration
replays the proof verifiers and stateless transition before trusting the tip;
an integration vector then continues with the next canonical block. V2 side
branches/reorg, live node and IBD/relay selection, real Ethereum settlement,
production proving artifacts, operations and independent audits still block
mainnet funds. See
`labs/usdom-reserve/docs/CANONICAL-V2-INGRESS-RECOVERY-ETAPA151-2026-10-18.txt`.

Stage 152 — candidate-v2 side branches and atomic reorganization (2026-10-18)

UDV2SC01 now retains the exact proof envelope and bounded execution witnesses
for a non-canonical V2 block. ChainState rewinds to the common ancestor,
replays every side package and witness, applies deterministic fork choice and
atomically promotes a stronger branch together with ordinary UTXOs, kernels,
V2 records, runtime tip and checkpoint floor. The directed vector corrupts a
sidecar and proves rejection without partial mutation, then restores it,
reorganizes A2 to B2/B3 and verifies restart recovery. Live node/IBD/relay/
mining selection, real Ethereum settlement, production proving artifacts,
operations and independent audits still block mainnet funds. See
`labs/usdom-reserve/docs/CANDIDATE-V2-SIDE-BRANCH-REORG-ETAPA152-2026-10-18.txt`.

Stage 153 — bounded external-verifier return data (2026-10-18)

The checkpoint registry no longer receives verifier output into dynamically
sized Solidity bytes. Both proof and configuration calls copy exactly one word
and reject any other RETURNDATASIZE, preventing a hostile verifier from forcing
an unbounded return-data copy. New tests reject 64-byte and one-megabyte
responses in the reserve and registry, including constructor configuration.
Production lint passes with warnings denied and stale-suppression reporting;
119 Solidity and 58 Node 24 tests pass. Production release hashes remain unset
and the readiness gates remain closed. See
`labs/usdom-reserve/docs/BOUNDED-VERIFIER-RETURNDATA-ETAPA153-2026-10-18.txt`.

Stage 154 — authenticated candidate-v2 wire envelope (2026-10-18)

UDOMV2W1 now carries the proof-bearing package and exact stateless witness
bundle atomically under a distinct command and bilateral authenticated
capability. The decoder rejects empty, oversized, truncated and trailing
representations, Noise reassembly is bounded to the feature's real maximum,
and the node applies the block anti-flood budget. The node does not yet
advertise or ingest the V2 command; live activation, runtime/IBD/orphan/relay/
mining integration, real Ethereum settlement, proving artifacts, operations
and independent audits still block mainnet funds. See
`labs/usdom-reserve/docs/CANDIDATE-V2-WIRE-ENVELOPE-ETAPA154-2026-10-18.txt`.

Stage 155 — atomic V1-to-V2 activation and runtime (2026-10-18)

The final V1 block now derives its actual parent hash and V1/V2 roots and
commits UDACTV02 in the same LMDB transaction as the block, ordinary economic
state, V1 recovery bytes and checkpoint floor. Wrong heights leave no partial
marker, corrupted marker pairs fail closed, and all V1 branch ingress stops
after activation. NativeUsdomV2Runtime restores the exact schedule, mandatory
verifier and V2 tip before accepting the first V2 child. The complete
dom-chain feature suite passed 250 tests. Node configuration/runtime switching
and V2 IBD/orphan/relay/mining integration still block mainnet funds. See
`labs/usdom-reserve/docs/ATOMIC-V1-V2-ACTIVATION-RUNTIME-ETAPA155-2026-10-18.txt`.

Stage 156 — hash-pinned V2 migration configuration (2026-10-18)

Native manifest schema 2 now requires an exact candidate-v2 first height above
the V1 activation boundary, while schema 1 cannot acquire V2 authority. The
manifest checker exposes the phase explicitly and the current V1-only startup
path refuses a V2 manifest instead of silently ignoring it. Four configuration
tests and all-target dom-node Clippy pass. Live runtime ownership switching and
V2 IBD/orphan/relay/mining integration still block mainnet funds. See
`labs/usdom-reserve/docs/HASH-PINNED-V2-MIGRATION-CONFIG-ETAPA156-2026-10-18.txt`.

Stage 157 — restart-safe V1/V2 node phase and boundary ingress (2026-10-18)

Schema-2 startup now restores exactly one phase from persisted consensus
state, checks both V1 and V2 schedules against the hash-pinned manifest, and
rejects a migration parent committed without its atomic marker. The final V1
wire ingress installs V2 in the same database transaction; after restart, the
node accepts an exact package/witness V2 envelope and survives another restart
at the V2 tip. A stale V1-tip restart guard discovered by this end-to-end test
was corrected. The full dom-chain feature suite, the directed node lifecycle
test and strict Clippy pass. V2 P2P/IBD/relay/orphan/mining and an in-memory
capability switch still block mainnet funds. See
`labs/usdom-reserve/docs/RESTART-SAFE-V1-V2-NODE-PHASE-ETAPA157-2026-10-18.txt`.

Stage 158 — authenticated V2 P2P, exact IBD and controlled phase restart (2026-10-19)

Candidate-V2 nodes now negotiate an exclusive authenticated V2 capability and
transport the exact package and execution-witness bundle through relay,
headers-first IBD, GetBlockData, future retention, orphan recovery and parent
fetch. Native bodies cannot be downgraded across ordinary, V1 and V2 commands.
The final V1 commit requests a coordinated restart after its atomic migration
marker is durable, so the restarted process advertises only V2. A two-node
test converges on the exact persisted V2 bytes, and the full dom-chain suite
and strict Clippy pass. The test terminology now states explicitly that PoW
mines DOM blocks; an empty USDOM V2 batch issues no USDOM. V2 DOM-miner template
integration, real Ethereum settlement, production proofs, operations and
independent audits still block mainnet funds. See
`labs/usdom-reserve/docs/AUTHENTICATED-V2-P2P-IBD-ETAPA158-2026-10-19.txt`.

Stage 159 — candidate-V2 DOM miner and monetary separation (2026-10-19)

The node miner now continues after V2 activation by building a normal PoW DOM
block whose header commits an independently revalidated USDOM V2 transition
batch and exact ordered witnesses. Its coinbase remains the ordinary DOM
reward; an empty USDOM batch preserves `total_issued == 0` and creates no
USDOM. A bounded volatile V2 pool verifies proof+witness pairs at admission,
template construction and final package ingress, removes confirmed candidates
and drops stale ones. A running server mines and relays the next V2 block to a
second authenticated node with byte-identical persistence. A production-facing
V2 candidate submission API, real Ethereum settlement, production proofs,
operations and independent audits still block mainnet funds. See
`labs/usdom-reserve/docs/V2-DOM-MINER-MONETARY-SEPARATION-ETAPA159-2026-10-19.txt`.

Stage 160 — authenticated binary V2 candidate ingress (2026-10-19)

The authenticated candidate-V2 RPC now accepts one canonical binary UDV2RPC1
proof-envelope/witness pair, with exact length framing, media-type enforcement
and an isolated ceiling covering the 8 MiB plus 4 MiB consensus maxima while
all ordinary routes retain their 1 MiB ceiling. One-at-a-time HTTP
backpressure prevents queued consensus-sized bodies from reaching the handler.
Live ingress, candidate admission and mining-template cryptography acquire
consensus locks asynchronously and execute on Tokio's blocking pool. Four RPC
tests, dom-node/dom-rpc compilation and strict all-target Clippy pass. A repeat
of the stage-159 two-node scenario remained in its debug Groth16 fixture for
over thirty minutes and was stopped without a result; the prior pass remains
the baseline and a controlled release-environment repeat is open. Real
Ethereum settlement, production proofs, operations and independent audits
still block mainnet funds. See
`labs/usdom-reserve/docs/AUTHENTICATED-BINARY-V2-CANDIDATE-INGRESS-ETAPA160-2026-10-19.txt`.

Stage 161 — exact V2 wallet candidate client (2026-10-19)

The strict loopback wallet client now submits the exact proof envelope and
ordered execution witnesses through the shared UDV2RPC1 encoder, bearer
authentication and application/octet-stream endpoint. It accepts only a
canonical nonzero queued candidate acknowledgement and never treats admission
as confirmation. Socket-level tests verify the complete request byte-for-byte
and reject malformed acknowledgements; strict all-target wallet Clippy passes.
A real finalized Ethereum deposit/payout vector, production proof artifacts,
release operations and independent audits still block mainnet funds. See
`labs/usdom-reserve/docs/EXACT-V2-WALLET-CANDIDATE-CLIENT-ETAPA161-2026-10-19.txt`.

Stage 162 — minimal shared V2 RPC protocol (2026-10-19)

UDV2RPC1 now lives in a dependency-minimal shared crate with one canonical
encoder, a borrowed decoder and independent 8 MiB envelope/4 MiB witness
ceilings. The server and wallet use this crate directly; the offline wallet no
longer imports the RPC server or its Axum/Tower graph. Compile-time assertions
make RPC and consensus limits change together. Eight directed tests, node
compilation and strict all-target Clippy pass. Ethereum settlement, production
proof artifacts, release operations and independent audits still block
mainnet funds. See
`labs/usdom-reserve/docs/MINIMAL-SHARED-V2-RPC-PROTOCOL-ETAPA162-2026-10-19.txt`.

Stage 163 — end-to-end V2 candidate ID binding (2026-10-19)

The shared candidate protocol now derives the domain-separated ID of the exact
proof envelope and witness bundle. The native pool uses that function and the
wallet recomputes it before submission, rejecting any queued acknowledgement
for another pair. Protocol and wallet tests, dom-chain/dom-node compilation and
strict all-target Clippy pass. Ethereum settlement, production proof artifacts,
release operations and independent audits still block mainnet funds. See
`labs/usdom-reserve/docs/END-TO-END-V2-CANDIDATE-ID-BINDING-ETAPA163-2026-10-19.txt`.

Stage 169 — immutable RISC Zero checkpoint adapter (2026-10-19)

DOMCheckpointRiscZeroVerifier now binds the checkpoint registry to one Ethereum
chain, immutable RISC Zero verifier bytecode, Groth16 selector, guest ImageID and
raw 32-byte checkpoint-statement journal. It rechecks code and selector on every
call, bounds seals to 64 KiB and returns only the registry's exact V2 proof
capability. Seven targeted tests include a full registry candidate submission,
and production lint passes with warnings denied. The checkpoint consensus guest,
positive 360-block witness, production ImageID and real receipt remain absent,
so mainnet and real funds stay blocked by construction. See
`labs/usdom-reserve/docs/CHECKPOINT-RISC0-EVM-ADAPTER-ETAPA169-2026-10-19.txt`.

Stage 170 — canonical immutable deposit-policy transport (2026-10-19)

StaticDepositTrustPolicy now has one exact 302-byte UDDPSP01 encoding covering
the finality bootstrap, all fork versions, reserve identity, runtime hash,
bridge domain and amount bound. Decode requires exact canonical re-encoding;
the dynamic slot ceiling remains derived from DOM consensus time. The full
Ethereum-finality crate passes 50 runtime tests and five compile-fail doctests,
plus strict Clippy. This removes one host-only configuration dependency needed
by a future checkpoint guest, but RandomX proof feasibility, bounded recursive
checkpoint inputs and production receipts remain open. See
`labs/usdom-reserve/docs/STATIC-DEPOSIT-POLICY-TRANSPORT-ETAPA170-2026-10-19.txt`.

Stage 171 — canonical recursive checkpoint segment state (2026-10-19)

CheckpointSegmentState now has one exact 1,073-byte UDCSEG01 encoding that
binds chain and policy identities, height and block, native and economic roots,
accumulated work and the complete checkpoint context. Strict decoding and a
domain-separated commitment provide the small public frontier required to
chain bounded block or chunk proofs without treating a theoretically multi-
gigabyte 390-block witness as one input. Nine default and 14 host-reference
tests pass, together with strict Clippy and rustfmt. No segment transition
guest, recursive aggregation or RandomX proof exists yet, so mainnet and real
funds remain blocked. See
`labs/usdom-reserve/docs/RECURSIVE-CHECKPOINT-SEGMENT-STATE-ETAPA171-2026-10-19.txt`.

Stage 172 — bounded checkpoint segment transition statement (2026-10-19)

CheckpointSegmentTransition now has one exact 2,190-byte UDCSTN01 encoding that
links two complete UDCSEG01 frontiers to a nonzero private-input commitment. It
limits a segment to 32 blocks, enforces the exact height delta, strictly
increasing work and immutable chain and verifier policies, and has its own
domain-separated commitment. Twelve default and 17 host-reference tests pass,
together with strict Clippy and rustfmt. This is the public receipt statement;
the guest that proves each committed block, RandomX work and state transition
and the recursive aggregator remain absent, so mainnet and real funds remain
blocked. See
`labs/usdom-reserve/docs/BOUNDED-CHECKPOINT-SEGMENT-TRANSITION-ETAPA172-2026-10-19.txt`.

Stage 173 — bounded checkpoint segment private input (2026-10-19)

CheckpointSegmentPrivateInput now has one canonical UDCSPI01 encoding for up to
32 ordered package/native-witness/economic-witness triples. It rejects inputs
above 64 MiB before component allocation, uses checked exact framing, commits
the bytes directly into UDCSTN01 and parses all components through their
consensus-owned decoders in host-reference mode. Fifteen default and 21 host-
reference tests pass with strict Clippy and rustfmt. The defensive 64 MiB cap is
not yet proven to cover every valid maximum-weight DOM block; large economic
transitions may require another recursive layer inside a block. The guest,
RandomX proof and receipt aggregation remain absent, so mainnet and real funds
remain blocked. See
`labs/usdom-reserve/docs/BOUNDED-CHECKPOINT-PRIVATE-INPUT-ETAPA173-2026-10-19.txt`.

Stage 174 — portable PoW consensus boundary (2026-10-19)

dom-pow now isolates its C/unsafe RandomX implementation behind the default
native-randomx feature while leaving ASERT, target/work arithmetic and the seed
schedule available to portable proof code. The checkpoint program disables the
native backend by default and enables it only for host-reference; cargo-tree
checks prove the portable graph excludes randomx-rs and the host graph retains
it. Both dom-node feature profiles compile, and the program still passes 15
portable and 21 host-reference tests with strict Clippy. This does not implement
RandomX inside the guest: a sound guest-compatible relation or bound recursive
receipt remains required, so mainnet and real funds remain blocked. See
`labs/usdom-reserve/docs/PORTABLE-POW-BOUNDARY-ETAPA174-2026-10-19.txt`.

Stage 175 — canonical RandomX proof statement (2026-10-19)

CheckpointRandomXStatement now has one exact 384-byte UDCRXST1 encoding that
binds the chain, RFC-0011 seed, complete 224-byte header PoW preimage, claimed
RandomX output and canonical expanded target. It rejects schedule, height,
target and work substitution and has a domain-separated receipt commitment.
Eighteen portable and 24 host-reference tests pass with strict Clippy, while the
portable graph remains free of randomx-rs. This statement does not compute
RandomX and cannot authorize PoW until a reviewed guest or equivalent recursive
receipt proves the relation, so mainnet and real funds remain blocked. See
`labs/usdom-reserve/docs/RANDOMX-PROOF-STATEMENT-ETAPA175-2026-10-19.txt`.

Stage 176 — exact parsed-header to RandomX statement binding (2026-10-19)

The host reference now derives UDCRXST1 directly from the parsed BlockHeader:
height, complete PoW preimage, claimed RandomX output and target cannot be
provided independently by a proof relayer. Nonce changes alter the statement
commitment and an unauthenticated seed rejects. Eighteen portable and 25 host-
reference tests pass with strict Clippy and rustfmt. The future segment guest
must reproduce this derivation and verify a real RandomX receipt; no such
receipt exists yet, so mainnet and real funds remain blocked. See
`labs/usdom-reserve/docs/RANDOMX-HEADER-BINDING-ETAPA176-2026-10-19.txt`.

Stage 177 — native RandomX reference relation (2026-10-19)

The checkpoint host reference now recomputes exact RandomX over the authenticated
seed and complete 224-byte PoW preimage before returning a UDCRXST1 commitment.
It fails closed on malformed statements, execution failure or any claimed-hash
mismatch. A fixed 224-byte known-answer vector and mutation tests exercise the
real native implementation; the portable profile still excludes RandomX FFI.
Eighteen portable and 27 host-reference tests pass with strict Clippy and
rustfmt. This oracle is not a guest or receipt and therefore does not authorize
checkpoint PoW, mainnet or real funds. See
`labs/usdom-reserve/docs/RANDOMX-NATIVE-REFERENCE-ETAPA177-2026-10-19.txt`.

Stage 178 — RandomX receipt ImageID binding (2026-10-19)

The recursive checkpoint frontier now uses the versioned 1,105-byte UDCSEG02
encoding and binds the exact nonzero RISC Zero ImageID authorized to prove
RandomX. The matching 2,254-byte UDCSTN02 transition rejects ImageID rotation,
and the receipt-assumption boundary derives the expected 32-byte journal from
the canonical UDCRXST1 commitment only when network and chain identities match.
UDCSEG01 and UDCSTN01 are superseded historical formats. This prevents a prover
from selecting a guest that merely echoes the claimed hash, but no production
ImageID, guest-compatible RandomX relation, receipt verifier or recursive
segment guest exists yet. Mainnet and real funds remain blocked. See
`labs/usdom-reserve/docs/RANDOMX-RECEIPT-IMAGEID-BINDING-ETAPA178-2026-10-19.txt`.

Stage 179 — checkpoint proof completion release gate (2026-10-19)

The closed-mainnet and real-funds gates now independently require nine concrete
checkpoint proof completion facts: complete private input, compiled guest,
pinned outer and inner ImageIDs, recursive segment execution and aggregation,
coverage of every valid block, a guest-compatible RandomX relation and its
receipt. A table test turns each fact off independently and proves that the
corresponding stable blocker appears. This prevents high-level readiness flags
from hiding an unfinished proving path. The checked-in configuration keeps the
missing facts false, so deployment and real funds remain blocked. See
`labs/usdom-reserve/docs/CHECKPOINT-PROOF-COMPLETION-GATE-ETAPA179-2026-10-19.txt`.

Stage 180 — RISC Zero checkpoint configuration reconciliation (2026-10-19)

The v6 checkpoint manifest now computes the exact configuration hash exposed by
DOMCheckpointRiscZeroVerifier, binding the Ethereum chain, deployed verifier
code, Groth16 selector, outer checkpoint guest ImageID and journal schema. It
also retains a separate complete proving-program configuration commitment and
fixes the UDCSEG02, UDCSTN02 and UDCRXST1 formats plus the inner RandomX receipt
ImageID. A fixed JavaScript/Solidity vector proves the ABI hashes agree. The
earlier v5 generic hash could not equal the deployed RISC Zero adapter hash;
that inconsistency failed closed and is now removed. Production ImageIDs remain
unconfigured, so mainnet and real funds stay blocked. See
`labs/usdom-reserve/docs/RISC0-CHECKPOINT-CONFIG-RECONCILIATION-ETAPA180-2026-10-19.txt`.

Stage 181 — RISC Zero RandomX receipt assumption boundary (2026-10-19)

The checkpoint program now has an optional RISC Zero 3.0.6 recursion boundary
that converts the state-pinned ImageID directly from its 32 bytes and, only in a
zkVM guest build, calls `env::verify` over the exact raw UDCRXST1 commitment.
A fixed 00-through-1f vector proves no byte or 32-bit word reversal occurs. The
default portable graph remains independent of RISC Zero and RandomX FFI. This
defines the sound call site but does not supply a RandomX guest or receipt, so
mainnet and real funds remain blocked. See
`labs/usdom-reserve/docs/RISC0-RANDOMX-ASSUMPTION-BOUNDARY-ETAPA181-2026-10-19.txt`.

Stage 182 — unforgeable segment-bound RandomX assumption (2026-10-19)

RandomX receipt assumptions can no longer be fabricated by external guest code:
their ImageID and journal fields are private, and the only public constructor
requires a valid UDCSTN02 transition plus a UDCRXST1 height strictly inside its
proved interval. Network, chain, statement and commitment checks still apply.
A compile-fail test proves direct field construction is impossible, and runtime
tests reject invalid transitions and receipts from before or after the segment.
The complete per-block guest loop and RandomX receipts remain unfinished, so
mainnet and real funds remain blocked. See
`labs/usdom-reserve/docs/UNFORGEABLE-SEGMENT-RANDOMX-ASSUMPTION-ETAPA182-2026-10-19.txt`.

Stage 183 — exact per-block RandomX receipt bindings (2026-10-19)

The host reference now derives one receipt requirement from every exact package
committed by UDCSPI01. It enforces consecutive heights, canonical parent and
terminal identifiers, chain-ID-bound genesis, consensus-selected seed anchors,
the complete rolling header context and the next context's seed anchors. The
old arbitrary-statement constructor is no longer externally callable, so a
guest cannot use it to skip, duplicate, reorder or substitute a header inside
the same segment. Tests also cross the height-2,048 RandomX epoch boundary. The
complete loop is not yet a compiled checkpoint guest and no production RandomX
guest, ImageID or receipt exists, so mainnet and real funds remain blocked. See
`labs/usdom-reserve/docs/EXACT-PER-BLOCK-RANDOMX-BINDINGS-ETAPA183-2026-10-19.txt`.

Stage 184 — portable zkVM segment receipt bindings (2026-10-19)

The exact per-block relation now builds behind a dependency-free
`segment-bindings` feature and compiles for `riscv32im-risc0-zkvm-elf`. Its
34-package graph excludes host consensus, dom-pow/primitive-types/RNG, native
RandomX, storage, async runtime, privacy and state crates. A bounded parser
derives the header, canonical block identifier, RandomX preimage, target and
authenticated seed directly from committed USDOMBL4 bytes. One hundred thousand
differential vectors match the authoritative PoW helpers, and host tests match
the typed BlockHeader path exactly. This is still a component of the future
checkpoint guest; full consensus/native execution and real recursive receipts
remain absent, so mainnet and real funds stay blocked. See
`labs/usdom-reserve/docs/PORTABLE-ZKVM-SEGMENT-BINDINGS-ETAPA184-2026-10-19.txt`.

Stage 185 — RISC Zero RandomX segment receipt aggregate (2026-10-19)

A dedicated RISC Zero 3.0.6 component guest now derives every exact per-header
receipt requirement, verifies the ordered set inside the zkVM and commits the
distinct UDCRXAG1 aggregate. Its 305,208-byte ProgramBinary rebuilds byte for
byte with SHA-256 `12766714f3b214b298f42c2ba5ee9f7828e48ce786ded867949323d9cae9b636`
and candidate ImageID
`8f66e353e0e7aeaa5f00ae4ec26e14dcc98c75b7ff6f6bcaa41079ea2f30af11`.
The component cannot authorize a checkpoint and has no positive inner RandomX
receipt yet, so production approval remains false. See
`labs/usdom-reserve/docs/RISC0-RANDOMX-SEGMENT-AGGREGATE-ETAPA185-2026-10-19.txt`.

Stage 186 — objective mainnet assurance policy (2026-10-19)

External audit reports and an impossible zero-risk guarantee are no longer
hard release requirements. The fail-closed gate instead requires an exact
security-validation report and explicit residual-risk acceptance, while all
technical, artifact, operational and authorization blockers remain enforced.
Tests prove both release modes can pass without external audits and still reject
missing objective evidence or malformed optional reports. See
`labs/usdom-reserve/docs/OBJECTIVE-MAINNET-ASSURANCE-POLICY-ETAPA186-2026-10-19.txt`.

Stage 187 — portable bit-exact RandomX kernel (2026-10-19)

A new safe-Rust kernel now reproduces the RandomX arithmetic, explicit rounding,
AES and Blake2 generators, program decoding, every bytecode class, the full
2,048-iteration scratchpad VM loop, chained seed and final hash without host
floating-point state or CPU AES instructions. Fifteen differential/reference
tests pass and the crate compiles for `riscv32im-risc0-zkvm-elf`. The Argon
cache, superscalar dataset derivation, end-to-end guest and positive receipt
remain unfinished, so the production RandomX relation remains false. See
`labs/usdom-reserve/docs/PORTABLE-RANDOMX-KERNEL-ETAPA187-2026-10-19.txt`.

Stage 188 — complete portable RandomX relation (2026-10-19)

The safe-Rust path now reproduces the complete RandomX v1 light relation,
including the 256 MiB Argon2d cache, exact superscalar generation/execution,
dataset derivation and the full eight-program hash. Its cache digest, generated
program shapes, dataset item and end-to-end digest match upstream RandomX
v1.2.1. A RISC Zero 3.0.6 candidate guest compiles and packages with ImageID
`b5188212cfe7c605049d0cc7945dcd38293ae5ea1f1f6efa3a6f027cef8f045c`.
The relation is implemented; a positive receipt, proving-cost measurements and
recursive verifier integration remain concrete release blockers. External audit
and impossible zero-risk guarantees are not blockers. See
`labs/usdom-reserve/docs/COMPLETE-PORTABLE-RANDOMX-RELATION-ETAPA188-2026-10-19.txt`.

Stage 189 — canonical RandomX receipt integration (2026-10-19)

The complete RandomX guest now accepts only the fixed 384-byte `UDCRXST1`
statement, validates its seed schedule, header preimage, target binding and
work threshold, recomputes the full light-mode hash, and publishes the exact
32-byte statement commitment expected by the recursive segment aggregate. The
reproducible ProgramBinary has SHA-256
`57712c3a644e5c90f46d683afeec21ab1460887a0cddf3006338618f2d0bac93`
and candidate ImageID
`2058876b522b931d981a56883eec727b8351634fb3904b712ae103b245c94a2c`.
A positive receipt, cost measurements, production ImageID ratification and the
outer consensus-transition guest remain objective release blockers; external
audit and absolute zero-risk guarantees do not. See
`labs/usdom-reserve/docs/RANDOMX-RECEIPT-INTEGRATION-ETAPA189-2026-10-19.txt`.

Stage 190 — segment policy input and stable RandomX statement boundary (2026-10-20)

A bounded canonical `UDCSPOL1` transport now supplies the DOM genesis,
candidate-v2 activation schedule, both immutable Ethereum trust policies and
the private-spend verifying key to a future segment guest. Typed validation
reconstructs every object and matches its network, chain, activation boundary,
registry configuration, bridge identity and verifier hash against `UDCSEG02`.
`UDCRXST1` now lives in the stable checkpoint-statement crate, so the complete
RandomX guest no longer links the full checkpoint execution crate merely to
parse its public input. Updated candidate ImageIDs are
`8efa49d4fe0f616840013adb1d3029ef71642099cb336c577a2691f7eea1dc24`
for the complete RandomX relation and
`08abf768e699ecb9d5cd2abc7603368103bcd3ee61afe9066d8a77272ac02ebf`
for its ordered segment aggregate. See
`labs/usdom-reserve/docs/SEGMENT-POLICY-AND-STABLE-RANDOMX-BOUNDARY-ETAPA190-2026-10-20.txt`.

The same stage isolates native RandomX behind the default `dom-consensus`
`native-randomx` feature. Node and chain builds retain native PoW validation,
while no-default-feature consumers exclude `randomx-rs`; full RV32 portability
still requires a reviewed portable boundary for `dom-crypto`.

Stage 191 — portable exact DOM Bulletproof verifier (2026-10-20)

`dom-bulletproof-portable` now verifies the exact 739-byte aggregated DOM range
proof in safe `no_std` Rust. Its 256 frozen generators were cross-checked with
both pinned Blockstream secp256k1-zkp and the legacy Grin C API. Differential
positive, mutation and context tests pass, and the portable consensus graph
excludes native crypto, RandomX FFI and OS randomness while the default node
keeps its native backends. See
`labs/usdom-reserve/docs/PORTABLE-BULLETPROOF-VERIFIER-ETAPA191-2026-10-20.txt`.

Stage 192 — complete portable checkpoint segment guest (2026-10-20)

The `UDCSNS01` native-state opening, portable policy reconstruction and full
segment executor now validate each DOM v4 block, native USDOM transition,
ordinary economic transition, Ethereum/private proof and exact RandomX receipt
binding. The complete RISC Zero segment guest compiles to a 3,013,444-byte ELF;
its ProgramBinary SHA-256 is
`eda0b228c59d88f23604ed4f0349ecb67e3099dbe6126f3b827af8bfc479bf65`
and candidate ImageID is
`3a30945b4d5e78a14b774e5bd0a3638b3f3fb42210129356fa798f5d6b28529f`.
See `labs/usdom-reserve/docs/PORTABLE-CHECKPOINT-SEGMENT-GUEST-ETAPA192-2026-10-20.txt`.

Stage 193 — outer checkpoint statement composition (2026-10-20)

The canonical `UDCOUT01` transport now composes up to 720 complete segment
receipts, forces exact boundaries at the proposed checkpoint and confirmation
tip, authenticates the previous registry state and commits only the Solidity
`UDCPST04` statement hash. Segments may contain 1 to 32 blocks, allowing the
prover to respect bounded package and witness inputs without crossing either
public boundary. The outer guest freezes the Stage 192 segment ImageID in its
executable. Its reproducible artifact identifiers are recorded in the Stage 193
assessment and provenance manifest.
The segment and outer artifacts reproduce byte-for-byte from empty build
targets. Positive recursive receipts, proving-cost measurement and production
configuration remain pending. External audit and an absolute
zero-risk guarantee are not release blockers. See
`labs/usdom-reserve/docs/OUTER-CHECKPOINT-COMPOSITION-ETAPA193-2026-10-20.txt`.

Stage 194 — bounded economic block chunks (2026-10-20)

The `UDECCW01` witness advances at most 512 sparse economic keys per chunk in
one deterministic sequence: UTXO effects followed by historical-kernel
insertions. This removes the need for one unbounded multiproof when a valid DOM
block has many inputs. A 601-effect differential vector crosses two UTXO chunks
and one kernel chunk and reaches the same roots as full-state execution. The
portable guest and recursive block-receipt aggregation remain pending, so the
all-valid-block coverage requirement remains false. See
`labs/usdom-reserve/docs/BOUNDED-ECONOMIC-CHUNKS-ETAPA194-2026-10-20.txt`.

Stage 195 — recursive economic block proof (2026-10-20)

The bounded `UDECTN01` chunk guest and `UDECCH01` block aggregator now cover the
full consensus block-weight range. The segment independently binds a recursive
`UDECBT01` receipt to the exact package, block identity, effect counts and both
economic roots, then verifies it under a compile-time pinned ImageID. The outer
guest pins the resulting segment ImageID. All four artifacts reproduced
byte-for-byte from a clean target. A positive end-to-end recursive receipt,
proving-cost measurement and production configuration remain objective release
criteria. External audit and an absolute zero-risk guarantee are not release
blockers; residual risk must be documented and accepted. See
`labs/usdom-reserve/docs/RECURSIVE-ECONOMIC-BLOCK-PROOF-ETAPA195-2026-10-20.txt`.

Stage 196 — positive economic chunk execution (2026-10-20)

The frozen economic-chunk ProgramBinary executed successfully under the official
RISC Zero 3.0.6 executor. The positive 1,207-byte DOM v4 package and 105-byte
witness produced the exact expected journal in 56,677,238 user cycles across 57
2^20 segments. This is an execution benchmark, not a cryptographic receipt or a
proving-cost measurement; those remain pending. Absolute zero risk and external
audit remain outside the hard release gate, while documented residual-risk
acceptance and concrete technical and operational criteria remain required. See
`labs/usdom-reserve/docs/POSITIVE-ECONOMIC-CHUNK-EXECUTION-ETAPA196-2026-10-20.txt`.

Stage 197 — mainnet native-state commitment and checkpoint fork choice (2026-10-20)

The scheduled public-network v4 validator now has an explicit mainnet vector
showing that the exact native USDOM batch commitment changes both the PoW
preimage and canonical header identifier, and that a substituted batch is
rejected. A second mainnet vector starts from native issuance and burn state,
binds an authenticated checkpoint capability to that exact state root, commits
the checkpoint atomically as consensus state and proves fork choice permits the
checkpoint height but rejects an ancestor below it. Wrong-network and
wrong-policy capabilities fail closed. This closes the implementation gaps for
the production header commitment and checkpoint reorg barrier; selecting and
ratifying the production activation schedule remains a separate release task.
External audit and absolute zero-risk guarantees remain outside the hard gate;
documented residual-risk acceptance remains required. See
`labs/usdom-reserve/docs/MAINNET-NATIVE-STATE-AND-CHECKPOINT-FORK-CHOICE-ETAPA197-2026-10-20.txt`.

Stage 198 — portable dom-consensus compiles for RISC Zero RV32 (2026-10-20)

The complete `dom-consensus` crate now compiles for
`riscv32im-risc0-zkvm-elf` with default features disabled and
`portable-crypto` enabled. The portable dependency gate confirms this graph
excludes native cryptography, OS randomness and RandomX FFI, while the default
consensus and node graphs retain native RandomX. This records the portability
result that became possible after Stages 190–191; it is not a receipt,
benchmark or production ImageID approval. See
`labs/usdom-reserve/docs/DOM-CONSENSUS-RISC0-RV32-COMPILE-ETAPA198-2026-10-20.txt`.

Stage 199 — canonical RISC Zero adapter ABI (2026-10-20)

Both immutable RISC Zero adapters now reject dirty right padding in the
32-byte ABI word returned by `SELECTOR()`. They also invoke the no-return
`verify` entrypoint through a bounded `staticcall` and require exactly empty
returndata. A successful call that returns `false`, noncanonical bytes or a
return bomb is rejected without copying attacker-controlled output. Hostile
vectors cover both finalized-burn and checkpoint adapters, and the complete
Solidity suite passes. See
`labs/usdom-reserve/docs/RISC0-SELECTOR-CANONICAL-ABI-ETAPA199-2026-10-20.txt`.

Stage 200 — RISC Zero adapter ABI release gate (2026-10-20)

Closed-mainnet and real-funds readiness now require all five adapter ABI
hardening guarantees from Stage 199. Independent negative vectors prove that
removing canonical `bytes4` selector padding, exact empty `verify` returndata,
or return-bomb resistance closes the release gate. These are objective code
requirements; external audit and an absolute zero-risk guarantee remain outside
the release gate. See
`labs/usdom-reserve/docs/RISC0-ADAPTER-ABI-RELEASE-GATE-ETAPA200-2026-10-20.txt`.

Stage 201 — panic-free Ethereum receipt and ancestry boundaries (2026-10-20)

The raw Ethereum verifier no longer uses infallible `expect` calls when turning
an EIP-2718 envelope into a receipt or selecting the endpoints of an untrusted
execution-header ancestry. Unsupported envelopes and empty ancestry inputs now
return ordinary verification errors. The Ethereum finality crate passes 50
runtime tests, 5 compile-fail API tests, formatting and strict Clippy. See
`labs/usdom-reserve/docs/ETHEREUM-UNTRUSTED-DECODE-PANIC-HARDENING-ETAPA201-2026-10-20.txt`.

Stage 202 — bounded RISC Zero guest host inputs (2026-10-20)

All seven RISC Zero guests now have an automated source boundary check. The six
guests with dynamic host input must validate a nonzero protocol maximum before
allocation and reading; the complete RandomX guest remains fixed-size. The
checker fails on an unreviewed new guest and its mutation self-test proves that
allocation moved before the bound is rejected. The control is part of source
provenance and both release-readiness modes. External audit and an absolute
zero-risk guarantee remain outside the release gate; documented residual-risk
acceptance remains required. See
`labs/usdom-reserve/docs/RISC0-GUEST-INPUT-BOUNDARY-ETAPA202-2026-10-20.txt`.

Stage 203 — panic-free Ethereum finality production boundary (2026-10-20)

The Ethereum finality client now converts unsupported execution-header variants
and every untrusted witness integer read into typed errors. It stores the last
validated execution view explicitly, so its public accessor remains infallible
without repeating a fallible header conversion. An inventory-pinned checker
forbids panic primitives across all six production sources and mutation tests
prove every forbidden primitive is detected. The control is part of provenance
and both release modes. External audit and an absolute zero-risk guarantee
remain outside the release gate; documented residual-risk acceptance remains
required. See
`labs/usdom-reserve/docs/ETHEREUM-FINALITY-PANIC-FREE-BOUNDARY-ETAPA203-2026-10-20.txt`.

Stage 204 — panic-free native USDOM state boundary (2026-10-20)

All public native-state, witness, projection, undo and sparse-tree decoders now
remain on typed-error paths when presented with malformed state. Runtime
invariants no longer rely on `expect` or `unreachable!`, and a source-inventory
checker rejects reintroduction of panic primitives in either production source.
Deterministic hostile-byte tests exercise all ten decoders. The checker and its
three-file crate manifest are required by provenance and both release modes.
External audit and an absolute zero-risk guarantee remain outside the release
gate; documented residual-risk acceptance remains required. See
`labs/usdom-reserve/docs/NATIVE-STATE-PANIC-FREE-BOUNDARY-ETAPA204-2026-10-20.txt`.

Stage 205 — panic-free native privacy boundary (2026-10-20)

The Poseidon note frontier now returns typed errors for broken occupancy
invariants, applies append updates atomically and keeps its widely used root
accessor total under corrupted in-memory state. The canonical frontier decoder
has a hostile-byte corpus through its exact maximum. An inventory-pinned source
checker covers the three production privacy sources and verifies a four-file
crate manifest; provenance and both release modes execute it directly. External
audit and an absolute zero-risk guarantee remain outside the release gate;
documented residual-risk acceptance remains required. See
`labs/usdom-reserve/docs/NATIVE-PRIVACY-PANIC-FREE-BOUNDARY-ETAPA205-2026-10-20.txt`.

Stage 206 — proof-program panic and host-input boundary (2026-10-20)

Eleven production sources across the finalized-burn, checkpoint, statement,
economic and prover programs are inventory-pinned and free of panic primitives.
Both host stdin entrypoints are checked to bound reads at the exact protocol
maximum plus one byte before `read_to_end`. The checker, mutation self-test and
manifest are part of provenance and both release modes. See
`labs/usdom-reserve/docs/PROOF-PROGRAM-PANIC-AND-INPUT-BOUNDARY-ETAPA206-2026-10-20.txt`.

Stage 207 — panic-free native wallet boundary (2026-10-20)

Nine production `expect` paths in note reservation, authenticated RPC history,
durable submission authorization and issuance summaries now fail through typed
errors or a reserved invalid identity. All five wallet production sources are
inventory-pinned and panic-primitive free. The six-file manifest and mutation
checker are required by provenance and both release modes. See
`labs/usdom-reserve/docs/NATIVE-WALLET-PANIC-FREE-BOUNDARY-ETAPA207-2026-10-20.txt`.

Stage 208 — verified-checkpoint wallet history finality (2026-10-20)

The wallet can claim finalized historical state only through an opaque
capability constructed from a verified Ethereum checkpoint with exact DOM
network, domain, policy, tip and state bindings. The node independently requires
that its installed consensus checkpoint floor cover the requested canonical
historical tip. Ordinary authenticated history continues to reject any
unsolicited finality claim. See
`labs/usdom-reserve/docs/VERIFIED-CHECKPOINT-WALLET-HISTORY-FINALITY-ETAPA208-2026-10-20.txt`.

Stage 209 — bounded consensus checkpoint floor (2026-10-20)

Finalized historical wallet scans now additionally reject a consensus checkpoint
floor above the node's currently observed canonical tip. This closes an explicit
range condition around the stage 208 capability while retaining exact network,
domain and canonical-hash checks. Verification evidence is under
`labs/usdom-reserve/results-stage209-2026-10-20/`.

Stage 210 — renewable withdrawal queue lease (2026-10-20)

An irreversible native USDOM burn no longer loses its collateral claim merely
because an Ethereum queue lease expires. The original validUntil remains bound
and proved as native admission data, while each proof admission creates a fresh
seven-day Ethereum queue lease. Expired unpaid entries can be discarded and the
same exact burn can be re-proved with a recent finality slot; paid burn and
request identifiers remain permanent. See
`labs/usdom-reserve/docs/RENEWABLE-WITHDRAWAL-QUEUE-LEASE-ETAPA210-2026-10-20.txt`.

Stage 211 — release-specific residual-risk acceptance draft (2026-10-20)

The release now has a concrete acceptance template covering USDT issuer control,
irreversible destinations, both consensus systems, proof soundness, privacy
correlation, wallet and multisig custody, availability, immutability, supply
chain and undiscovered defects. It cannot satisfy the gate until the exact
release identities and evidence hashes are filled and the completed digest is
explicitly ratified. This records residual risk without treating an impossible
zero-risk guarantee or an external audit as a release requirement. See
`labs/usdom-reserve/docs/RESIDUAL-RISK-ACCEPTANCE-DRAFT-ETAPA211-2026-10-20.txt`.

Stage 212 — historical burn reproof under fresh finality (2026-10-20)

The portable finalized-burn relation now has an explicit regression vector for
renewable claims. It proves the same permanent burn-set entry after Ethereum
finality has advanced 30 days beyond the original native validUntil, retains
that original intent field and binds the new finalized Beacon slot into a new
Solidity statement. This verifies the stage 210 liveness fix across the proof
boundary without generating a heavy RISC Zero receipt. See
`labs/usdom-reserve/docs/HISTORICAL-BURN-FRESH-FINALITY-REPROOF-ETAPA212-2026-10-20.txt`.
