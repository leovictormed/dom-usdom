#!/usr/bin/env node
import {prepareSafeControlDeployments} from '../sdk/safe-control-deployment.mjs';

try {
  const result = await prepareSafeControlDeployments({
    owner: process.env.USDOM_SAFE_OWNER,
    rpcUrl: process.env.ETHEREUM_RPC_URL,
  });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`Safe control preparation failed: ${error.message}\n`);
  process.exitCode = 1;
}
