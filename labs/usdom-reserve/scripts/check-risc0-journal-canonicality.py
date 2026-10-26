#!/usr/bin/env python3
"""Audit canonical 32-byte journals and cross-proof domain separation."""
from pathlib import Path
import argparse,sys
ROOT=Path(__file__).resolve().parents[3]
GUESTS={
 'randomx':('crates/dom-usdom-randomx-risc0-guest/src/main.rs','.commitment()'),
 'aggregate':('crates/dom-usdom-randomx-aggregate-risc0-guest/src/main.rs','aggregate.commitment()'),
 'economic_chunk':('crates/dom-usdom-economic-chunk-risc0-guest/src/main.rs','executed.commitment()'),
 'economic_block':('crates/dom-usdom-economic-block-risc0-guest/src/main.rs','execution.block_commitment()'),
 'checkpoint_segment':('crates/dom-usdom-checkpoint-segment-risc0-guest/src/main.rs','executed.transition_commitment()'),
 'checkpoint_outer':('crates/dom-usdom-checkpoint-outer-risc0-guest/src/main.rs','executed.statement_hash()'),
 'finalized_burn':('crates/dom-usdom-finalized-burn-risc0-guest/src/main.rs','execution.output().as_bytes()'),
}
DOMAIN_MARKERS={
 'statement':'CHECKPOINT_RANDOMX_STATEMENT_DOMAIN',
 'program':'CHECKPOINT_RANDOMX_AGGREGATE_DOMAIN',
 'economic':'TRANSITION_DOMAIN',
 'economic_block':'BLOCK_TRANSITION_DOMAIN',
 'segment':'CHECKPOINT_SEGMENT_TRANSITION_DOMAIN',
 'checkpoint':'V4_TYPE_STRING',
 'burn':'FINALIZED_BURN_STATEMENT_TYPE',
}
SOURCES={
 'statement':'crates/dom-usdom-checkpoint-statement/src/lib.rs',
 'program':'crates/dom-usdom-checkpoint-program/src/lib.rs',
 'economic':'crates/dom-usdom-checkpoint-program/src/economic_chunks.rs',
 'economic_block':'crates/dom-usdom-checkpoint-program/src/economic_chunks.rs',
 'segment':'crates/dom-usdom-checkpoint-program/src/lib.rs',
 'checkpoint':'crates/dom-usdom-checkpoint-statement/src/lib.rs',
 'burn':'crates/dom-usdom-finalized-burn-program/src/lib.rs',
}

def audit(guests:dict[str,str],sources:dict[str,str],adapters:dict[str,str])->None:
 if len(guests)!=7 or len(set(GUESTS.values()))!=7: raise ValueError('journal inventory is not exactly seven distinct guests')
 for name,(_,expression) in GUESTS.items():
  source=guests[name]
  if source.count('env::commit_slice(')!=1: raise ValueError(f'{name}: journal must use exactly one commit_slice')
  if expression not in source: raise ValueError(f'{name}: unexpected journal expression')
  if 'env::commit(' in source: raise ValueError(f'{name}: serde-framed journal is forbidden')
 for key,marker in DOMAIN_MARKERS.items():
  source=sources[key]
  if marker not in source: raise ValueError(f'{key}: missing journal domain/version marker')
  if key in ('checkpoint','burn') and 'Keccak256::digest' not in source:
   raise ValueError(f'{key}: missing typed statement hash')
 for name,source in adapters.items():
  for marker in ('proof.length != EVM_PROOF_BYTES','bytes4(proof[:4]) != verifierSelector','sha256(abi.encodePacked(statementHash))','IRiscZeroVerifierV3.verify, (proof, imageId, digest)'):
   if marker not in source: raise ValueError(f'{name}: missing canonical EVM journal/proof marker')
 # Fixed 32-byte journal comparison prevents prefix/trailing-byte acceptance.
 for relative in ('crates/dom-usdom-randomx-proof-host/src/lib.rs','crates/dom-usdom-randomx-proof-host/src/aggregate.rs','crates/dom-usdom-economic-proof-host/src/lib.rs','crates/dom-usdom-checkpoint-proof-host/src/lib.rs','crates/dom-usdom-finalized-burn-proof-host/src/lib.rs'):
  source=(ROOT/relative).read_text()
  if 'journal.bytes.as_slice() !=' not in source: raise ValueError(f'{relative}: exact journal comparison absent')

def load():
 guests={name:(ROOT/path).read_text() for name,(path,_) in GUESTS.items()}
 sources={key:(ROOT/path).read_text() for key,path in SOURCES.items()}
 adapters={name:(ROOT/f'labs/usdom-reserve/contracts/{name}.sol').read_text() for name in ('DOMCheckpointRiscZeroVerifier','DOMFinalizedBurnRiscZeroVerifier')}
 return guests,sources,adapters

def main():
 parser=argparse.ArgumentParser(); parser.add_argument('--self-test',action='store_true'); args=parser.parse_args()
 guests,sources,adapters=load(); audit(guests,sources,adapters)
 if args.self_test:
  bad=dict(guests); bad['randomx']=bad['randomx'].replace('env::commit_slice(&journal);','env::commit(&journal);')
  try: audit(bad,sources,adapters)
  except ValueError: pass
  else: raise ValueError('serde-framed journal mutation accepted')
  bad_sources=dict(sources); bad_sources['burn']=bad_sources['burn'].replace('FINALIZED_BURN_STATEMENT_TYPE','UNTYPED_BURN')
  try: audit(guests,bad_sources,adapters)
  except ValueError: pass
  else: raise ValueError('cross-proof domain mutation accepted')
 print('PASS: 7/7 journals are exact 32-byte, typed/domain-separated and EVM-bound')
if __name__=='__main__':
 try: main()
 except (OSError,ValueError) as error: print(f'FAIL: {error}',file=sys.stderr); raise SystemExit(1)
