import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  AbiCoder,
  ContractFactory,
  Interface,
  JsonRpcProvider,
  NonceManager,
  Wallet,
  concat,
  encodeRlp,
  keccak256,
  toBeHex,
  zeroPadValue,
} from "ethers";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const reserveDirectory = resolve(scriptDirectory, "..");
const repository = resolve(reserveDirectory, "../..");
const finalityDirectory = join(repository, "labs", "usdom-ethereum-finality");
const outputPath = resolve(
  process.argv[2] ?? join(finalityDirectory, "fixtures", "local-reserve-receipts.json"),
);
const rpcUrl = process.env.RPC_URL ?? "http://127.0.0.1:18545";
const developmentKey =
  process.env.ANVIL_PRIVATE_KEY ??
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

function artifact(relativePath) {
  return JSON.parse(readFileSync(join(reserveDirectory, "out", relativePath), "utf8"));
}

function minimalQuantity(value) {
  const quantity = BigInt(value);
  return quantity === 0n ? "0x" : toBeHex(quantity);
}

function encodedReceipt(receipt) {
  const payload = encodeRlp([
    minimalQuantity(receipt.status),
    minimalQuantity(receipt.cumulativeGasUsed),
    receipt.logsBloom,
    receipt.logs.map((log) => [log.address, log.topics, log.data]),
  ]);
  const type = BigInt(receipt.type);
  return type === 0n ? payload : concat([toBeHex(type, 1), payload]);
}

async function deployed(wallet, relativeArtifact, arguments_) {
  const compiled = artifact(relativeArtifact);
  const contract = await new ContractFactory(compiled.abi, compiled.bytecode.object, wallet).deploy(...arguments_);
  await contract.waitForDeployment();
  return contract;
}

const rpc = new URL(rpcUrl);
if (!["127.0.0.1", "localhost", "[::1]"].includes(rpc.hostname)) {
  throw new Error("fixture generation is restricted to a loopback Anvil endpoint");
}
const provider = new JsonRpcProvider(rpcUrl, 31337, { staticNetwork: true });
if (BigInt(await provider.send("eth_chainId", [])) !== 31_337n) {
  throw new Error("fixture generation requires local chain ID 31337");
}
const wallet = new Wallet(developmentKey, provider);
const signer = new NonceManager(wallet);
const token = await deployed(signer, "Mocks.sol/HostileToken.json", []);
const governance = await deployed(signer, "Mocks.sol/MockGovernance.json", []);
const guardian = await deployed(signer, "Mocks.sol/MockGovernance.json", []);
const verifier = await deployed(
  signer,
  "USDOMProofReserve.t.sol/MockFinalizedBurnVerifier.json",
  [],
);
const domain = keccak256(new TextEncoder().encode("DOM local proof reserve fixture"));
const activation = keccak256(new TextEncoder().encode("DOM local activation fixture"));
const checkpointRegistry = await deployed(
  signer,
  "Mocks.sol/MockGracefulShutdownRegistry.json",
  [domain, activation],
);
const reserve = await deployed(signer, "USDOMProofReserve.sol/USDOMProofReserve.json", [
  [
    await token.getAddress(),
    await verifier.getAddress(),
    await checkpointRegistry.getAddress(),
    domain,
    activation,
    await governance.getAddress(),
    await guardian.getAddress(),
    86_400,
    172_800,
    100_000_000_000,
    2_000_000_000,
    false,
  ],
]);

await (await token.mint(wallet.address, 10_000_000)).wait();
await (await token.approve(await reserve.getAddress(), 10_000_000)).wait();
await provider.send("evm_setAutomine", [false]);
const fee = await provider.getFeeData();
const common = {
  gasLimit: 500_000,
  maxFeePerGas: fee.maxFeePerGas,
  maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
};
const first = await reserve.deposit(
  1_000_000,
  zeroPadValue("0x01", 32),
  `0x${"18".repeat(32)}`,
  common,
);
const second = await reserve.deposit(
  2_000_000,
  zeroPadValue("0x02", 32),
  `0x${"29".repeat(32)}`,
  common,
);
await provider.send("evm_mine", []);
await provider.send("evm_setAutomine", [true]);
const firstReceipt = await first.wait();
const secondReceipt = await second.wait();
if (firstReceipt.blockHash !== secondReceipt.blockHash) throw new Error("deposits were not mined together");

const block = await provider.send("eth_getBlockByHash", [firstReceipt.blockHash, false]);
const receipts = await provider.send("eth_getBlockReceipts", [firstReceipt.blockHash]);
const rawReceipts = receipts.map(encodedReceipt);
const temporary = mkdtempSync(join(tmpdir(), "usdom-receipts-"));
const receiptInput = join(temporary, "receipts.json");
writeFileSync(receiptInput, `${JSON.stringify(rawReceipts)}\n`);
const proofRun = spawnSync(
  process.env.CARGO ?? "cargo",
  ["run", "--quiet", "--manifest-path", join(finalityDirectory, "Cargo.toml"), "--example", "receipt_proofs", "--", receiptInput],
  { cwd: repository, encoding: "utf8" },
);
rmSync(temporary, { recursive: true, force: true });
if (proofRun.status !== 0) throw new Error("receipt proof generator failed");
const receiptProofs = JSON.parse(proofRun.stdout);
if (receiptProofs.root.toLowerCase() !== block.receiptsRoot.toLowerCase()) {
  throw new Error(`receipt root mismatch: ${receiptProofs.root} != ${block.receiptsRoot}`);
}

const reserveAddress = await reserve.getAddress();
const account = await provider.send("eth_getProof", [reserveAddress, [], block.number]);
const code = await provider.send("eth_getCode", [reserveAddress, block.number]);
const reserveInterface = new Interface(artifact("USDOMProofReserve.sol/USDOMProofReserve.json").abi);
const depositedTopic = reserveInterface.getEvent("Deposited").topicHash;
const transactionHashes = [firstReceipt.hash, secondReceipt.hash];
const fixtures = transactionHashes.map((hash) => {
  const receipt = receipts.find((candidate) => candidate.transactionHash.toLowerCase() === hash.toLowerCase());
  if (!receipt) throw new Error(`missing receipt ${hash}`);
  const transactionIndex = Number(BigInt(receipt.transactionIndex));
  const receiptLogIndex = receipt.logs.findIndex(
    (log) => log.address.toLowerCase() === reserveAddress.toLowerCase() && log.topics[0] === depositedTopic,
  );
  if (receiptLogIndex < 0) throw new Error(`missing Deposited log ${hash}`);
  const decoded = reserveInterface.decodeEventLog("Deposited", receipt.logs[receiptLogIndex].data, receipt.logs[receiptLogIndex].topics);
  return {
    transactionIndex,
    receiptLogIndex,
    proof: receiptProofs.proofs[transactionIndex],
    receipt: rawReceipts[transactionIndex],
    deposit: {
      depositId: decoded.id,
      funder: decoded.funder.toLowerCase(),
      amount: decoded.amount.toString(),
      receivingCommitment: decoded.receivingCommitment,
    },
  };
});

const output = {
  scope: "Local chain 31337; proof-reserve receipt/account/code MPT evidence; synthetic Beacon finality; not mint authority.",
  reserve: reserveAddress,
  token: await token.getAddress(),
  block,
  reserveAccount: {
    address: reserveAddress.toLowerCase(),
    balance: account.balance,
    codeHash: keccak256(code),
    nonce: account.nonce,
    storageHash: account.storageHash,
    accountProof: account.accountProof,
    storageProof: account.storageProof,
    code,
  },
  receipts,
  fixtures,
};
writeFileSync(outputPath, `${JSON.stringify(output, null, 2)}\n`);
console.log(outputPath);
