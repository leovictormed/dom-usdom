#!/usr/bin/env python3
from pathlib import Path

root=Path(__file__).resolve().parents[1]
execution=(root/'sdk/mainnet-deployment-execution.mjs').read_text()
executor=(root/'scripts/execute-mainnet-deployment.sh').read_text()
sequence=(root/'scripts/check-mainnet-deployment-sequence-cost.mjs').read_text()
deposit=(root/'sdk/closed-mainnet-deposit.mjs').read_text()
checks={
 'deployment fee cap 100 gwei':'MAINNET_DEPLOYMENT_MAX_FEE_PER_GAS=100_000_000_000n' in execution,
 'deployment tx cap 0.6 ETH':'MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST=600_000_000_000_000_000n' in execution,
 'deployment aggregate cap 1 ETH':'MAINNET_DEPLOYMENT_MAX_SEQUENCE_COST=1_000_000_000_000_000_000n' in execution and 'cumulative>MAINNET_DEPLOYMENT_MAX_SEQUENCE_COST' in sequence,
 'raw tx zero value':'transaction.value!==0n' in execution,
 'raw tx cost BigInt bound':'gasLimit*maxFee>MAINNET_DEPLOYMENT_MAX_TRANSACTION_COST' in execution,
 'executor fee cap':'fee>100000000000n' in executor,
 'executor cost cap':'600000000000000000n' in executor,
 'executor cumulative rechecks':executor.count('check-mainnet-deployment-sequence-cost.mjs')==2,
 'deployer balance max 1 ETH':executor.count('b>1000000000000000000n')==3,
 'counterfactual contract balance zero':executor.count('rpc balance "$expected"')>=3,
 'deposit exact 1 USDT':'CLOSED_MAINNET_DEPOSIT_AMOUNT=1_000_000n' in deposit,
 'exposure exact pilot':'BigInt(configuration.maxOutstandingBaseUnits)!==CLOSED_MAINNET_DEPOSIT_AMOUNT' in deposit,
 'outflow exact pilot':'BigInt(configuration.outflowCapacityBaseUnitsPerDay)!==CLOSED_MAINNET_DEPOSIT_AMOUNT' in deposit,
 'allowance reset':"'approve',[configuration.reserve,0n]" in deposit,
 'allowance exact':"'approve',[configuration.reserve,CLOSED_MAINNET_DEPOSIT_AMOUNT]" in deposit,
 'deposit not authorized':"broadcastAuthorized:false" in deposit,
}
failed=[name for name,ok in checks.items() if not ok]
if failed: raise SystemExit('financial bounds gate failed: '+', '.join(failed))
print(f'financial bounds gate: {len(checks)}/{len(checks)} passed')
