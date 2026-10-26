#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[1]
reader = (root / 'sdk/direct-project-file.mjs').read_text()
assert 'constants.O_RDONLY|constants.O_DIRECTORY|constants.O_NOFOLLOW' in reader
assert 'constants.O_RDONLY|constants.O_NOFOLLOW' in reader
assert 'before.nlink!==1n' in reader
assert 'before.uid!==expectedUid' in reader
assert '(before.mode&0o022n)!==0n' in reader
assert 'realpath(`/proc/self/fd/${handle.fd}`)' in reader
assert 'sameFile(before,after)' in reader
assert 'sameDirectory(directoryBefore,directoryAfter)' in reader

core = (root / 'scripts/prepare-production-release-core-materialization.mjs').read_text()
pre = (root / 'scripts/prepare-production-preactivation-core-materialization.mjs').read_text()
readiness = (root / 'scripts/check-mainnet-readiness.mjs').read_text()
setup = (root / 'scripts/prepare-trusted-setup-decision-report.mjs').read_text()
for text in (core, pre, readiness, setup):
    assert 'readDirectProjectFile' in text
assert 'const snapshots=new Map()' in core and 'input changed' in core
assert 'const snapshots=new Map()' in pre and 'input changed' in pre
assert 'const authorityFileBytes=new Map()' in readiness
assert 'assertEvidenceByteSnapshotsUnchanged' in readiness
assert 'transcriptAfter.equals(transcriptBytes)' in setup
print('release-crypto-artifact-file-boundary: PASS')
