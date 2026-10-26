import {removePrivateFileDurableIfExists} from '../sdk/durable-private-file.mjs';

if(process.argv.length!==3||!process.argv[2]) {
  console.error('Usage: node scripts/remove-private-file-durable.mjs ABSOLUTE_FILE');
  process.exitCode=2;
} else {
  await removePrivateFileDurableIfExists(process.argv[2]);
}
