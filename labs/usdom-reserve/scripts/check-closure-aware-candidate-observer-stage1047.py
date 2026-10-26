#!/usr/bin/env python3
"""Static gate for closure-aware checkpoint candidate observation."""
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
def require(path,*needles):
 text=(ROOT/path).read_text(); missing=[n for n in needles if n not in text]
 if missing: raise SystemExit(f"{path}: missing {missing}")
require('labs/usdom-reserve/scripts/observe-authenticated-checkpoint.mjs',
 'checkpoint-statement-v6.bin','uint128 totalIssued,uint128 totalBurned,bool issuanceClosed',
 'function gracefullyShutdown() view returns (bool)',
 'function latestIssuanceClosed() view returns (bool)',
 'function candidateIssuanceClosed() view returns (bool)',
 'totalIssued:decimal(candidate.totalIssued)',
 'issuanceClosed:candidateIssuanceClosed')
require('labs/usdom-reserve/sdk/checkpoint-candidate-observer.mjs',
 "'gracefullyShutdown','latestIssuanceClosed'", "'totalIssued','totalBurned','issuanceClosed'",
 "registry_gracefully_shutdown", 'observation.registry.latestIssuanceClosed===checkpoint.issuanceClosed',
 'candidate.issuanceClosed===checkpoint.issuanceClosed')
require('labs/usdom-reserve/sdk/checkpoint-submission.mjs',
 'checkpoint-statement-v6.bin','parseCheckpointStatementV6')
require('labs/usdom-reserve/test/node/checkpoint-submission.test.mjs',
 'UDCPST06 decoding', "blocker.code==='candidate_fields_mismatch'",
 'gracefullyShutdown:true')
print('stage1047 closure-aware candidate observer gate: ok')
