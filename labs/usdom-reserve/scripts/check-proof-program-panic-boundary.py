#!/usr/bin/env python3
"""Pin proof-program sources and reject production panic primitives."""
import hashlib, re, sys
from pathlib import Path

REPO=Path(__file__).resolve().parents[3]
MANIFEST=REPO/'labs/usdom-reserve/PROOF-PROGRAM-MANIFEST.sha256'
SOURCES={
 'crates/dom-usdom-finalized-burn-program/src/lib.rs',
 'crates/dom-usdom-finalized-burn-program/src/main.rs',
 'crates/dom-usdom-checkpoint-program/src/economic_chunks.rs',
 'crates/dom-usdom-checkpoint-program/src/lib.rs',
 'crates/dom-usdom-checkpoint-program/src/outer.rs',
 'crates/dom-usdom-checkpoint-program/src/portable.rs',
 'crates/dom-usdom-checkpoint-program/src/reference.rs',
 'crates/dom-usdom-checkpoint-statement/src/lib.rs',
 'crates/dom-usdom-checkpoint-statement/src/main.rs',
 'crates/dom-usdom-economic-block-program/src/lib.rs',
 'crates/dom-usdom-prover/src/lib.rs',
}
PANIC=re.compile(r'\.(?:unwrap|expect)\s*\(|\b(?:panic|unreachable|todo|unimplemented)!\s*\(')
LINE=re.compile(r'^([0-9a-f]{64})  (.+)$')

def fail(message): raise SystemExit(f'FAIL: {message}')
def production(source):
 return '\n'.join(x for x in source.split('#[cfg(test)]',1)[0].splitlines()
                  if not x.lstrip().startswith('//'))
def check_text(source,label):
 checked=production(source); match=PANIC.search(checked)
 if match: fail(f'{label}: panic primitive {match.group(0)!r}')

def check():
 for name in sorted(SOURCES): check_text((REPO/name).read_text(),name)
 listed={}
 for number,line in enumerate(MANIFEST.read_text().splitlines(),1):
  match=LINE.fullmatch(line)
  if not match or match.group(2) in listed: fail(f'malformed or duplicate manifest line {number}')
  name=match.group(2); candidate=REPO/name; resolved=candidate.resolve()
  if candidate.is_symlink() or not resolved.is_relative_to(REPO.resolve()) or not resolved.is_file():
   fail(f'invalid manifest path: {name}')
  digest=hashlib.sha256(resolved.read_bytes()).hexdigest()
  if digest != match.group(1): fail(f'manifest digest mismatch: {name}')
  listed[name]=digest
 if set(listed)!=SOURCES: fail('proof-program manifest inventory mismatch')
 finalized=(REPO/'crates/dom-usdom-finalized-burn-program/src/main.rs').read_text()
 statement=(REPO/'crates/dom-usdom-checkpoint-statement/src/main.rs').read_text()
 if finalized.find('.take(maximum_read as u64)') > finalized.find('.read_to_end(') or 'checked_add(1)' not in finalized:
  fail('finalized-burn host input is not bounded before read_to_end')
 if statement.find('.take((CHECKPOINT_STATEMENT_V4_BYTES + 1) as u64)') > statement.find('.read_to_end('):
  fail('checkpoint-statement host input is not bounded before read_to_end')

def self_test():
 for primitive in ['x.unwrap()','x.expect("x")','panic!("x")','unreachable!()','todo!()','unimplemented!()']:
  try: check_text(f'fn f(){{{primitive};}}','mutation')
  except SystemExit: pass
  else: raise AssertionError(primitive)
 print('PASS: proof-program checker rejects all panic primitives')

if sys.argv[1:]==['--self-test']: self_test()
elif not sys.argv[1:]:
 check(); print('PASS: 11 proof-program sources are panic-primitive free, host reads bounded, manifest verified')
else: fail('usage: check-proof-program-panic-boundary.py [--self-test]')
