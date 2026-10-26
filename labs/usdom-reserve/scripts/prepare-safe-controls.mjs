#!/usr/bin/env node
process.stderr.write(
  'Unsafe 1-of-1 Safe preparation is disabled. Use npm run --silent prepare:recoverable-safe-controls.\n',
);
process.exitCode=1;
