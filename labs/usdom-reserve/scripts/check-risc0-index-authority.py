#!/usr/bin/env python3
"""Static audit of JSON authority boundaries feeding all seven proof hosts."""
from pathlib import Path
import argparse,re,sys
ROOT=Path(__file__).resolve().parents[3]
HOSTS=(
 'crates/dom-usdom-randomx-proof-host/src/lib.rs',
 'crates/dom-usdom-randomx-proof-host/src/aggregate.rs',
 'crates/dom-usdom-economic-proof-host/src/lib.rs',
 'crates/dom-usdom-checkpoint-proof-host/src/lib.rs',
 'crates/dom-usdom-finalized-burn-proof-host/src/lib.rs',
)
REQUIRED={
 HOSTS[0]:('source.statement_count != source.statements.len()','record.index != expected_index','record.statement_file != statement_name(expected_index)','published_plan_bytes != rebuilt_plan_bytes'),
 HOSTS[1]:('receipts.receipt_count != receipts.receipts.len()','record.index != index','record.receipt_file != job.receipt_file','published != rebuilt'),
 HOSTS[2]:('source.segment_count != source.segments.len()','economic.block_count != economic.blocks.len()','record.chunk_count != record.chunks.len()','published != rebuilt'),
 HOSTS[3]:('source.segment_count != source.segments.len()','receipt_index.receipt_count != receipt_index.receipts.len()','published != rebuilt','receipt_index.segment_receipt_count != built.segment_receipt_count'),
 HOSTS[4]:('decoded_index != expected_index || published_index != expected_index_bytes','decoded_job != expected_job || published_job != expected_job_bytes','receipt_index != expected_receipt || receipt_index_bytes != expected_receipt_bytes'),
}

def audit(texts:dict[str,str])->None:
 if len(texts)!=5: raise ValueError('host inventory changed')
 total=0
 for path,source in texts.items():
  derives=list(re.finditer(r'#\[derive\([^\]]*Deserialize[^\]]*\)\]\s*#\[serde\(deny_unknown_fields\)\]\s*(?:pub\s+)?struct\s+([A-Za-z0-9_]+)',source))
  declared=len(re.findall(r'#\[derive\([^\]]*Deserialize[^\]]*\)\]\s*(?:#\[[^\]]+\]\s*)*(?:pub\s+)?struct\s+[A-Za-z0-9_]+',source))
  if len(derives)!=declared: raise ValueError(f'{path}: a deserialized struct lacks deny_unknown_fields')
  total+=declared
  if 'serde_json::from_slice' not in source: raise ValueError(f'{path}: no bounded typed JSON decoder')
  for marker in REQUIRED[path]:
   if marker not in source: raise ValueError(f'{path}: missing authority invariant: {marker}')
  if 'read_direct' not in source and 'read_direct_regular_file' not in source:
   raise ValueError(f'{path}: indexes are not read through bounded direct-file helper')
 if total < 25: raise ValueError('unexpectedly small typed-index inventory')
 # Serde derives reject duplicate struct fields; deny_unknown closes extension
 # ambiguity. Canonical generated plans are additionally byte-compared above.

def main():
 parser=argparse.ArgumentParser(); parser.add_argument('--self-test',action='store_true'); args=parser.parse_args()
 texts={path:(ROOT/path).read_text() for path in HOSTS}; audit(texts)
 if args.self_test:
  bad=dict(texts); target=HOSTS[0]; bad[target]=bad[target].replace('#[serde(deny_unknown_fields)]','#[serde(default)]',1)
  try: audit(bad)
  except ValueError: pass
  else: raise ValueError('unknown-field mutation accepted')
  bad=dict(texts); target=HOSTS[4]; bad[target]=bad[target].replace('decoded_index != expected_index || published_index != expected_index_bytes','false',1)
  try: audit(bad)
  except ValueError: pass
  else: raise ValueError('canonical re-encoding mutation accepted')
 print('PASS: five hosts/seven proof paths enforce strict bounded index authority')
if __name__=='__main__':
 try: main()
 except (OSError,ValueError) as error: print(f'FAIL: {error}',file=sys.stderr); raise SystemExit(1)
