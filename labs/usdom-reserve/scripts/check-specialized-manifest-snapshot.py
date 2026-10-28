#!/usr/bin/env python3
"""Take one final descriptor-bound snapshot of every specialized manifest."""
from pathlib import Path
import sys
from specialized_manifest import direct, manifest

REPO=Path(__file__).resolve().parents[3]
SETS=(
 (REPO,"labs/usdom-reserve/PROOF-PROGRAM-MANIFEST.sha256"),
 (REPO/"crates/dom-usdom-state","MANIFEST.sha256"),
 (REPO/"crates/dom-usdom-privacy","MANIFEST.sha256"),
 (REPO/"crates/dom-usdom-wallet","MANIFEST.sha256"),
 (REPO/"labs/usdom-ethereum-finality","MANIFEST.sha256"),
)
def global_pass():
 result=[]
 for root,name in SETS:result.append((root,name,direct(root,name),manifest(root,name)))
 return result
def verify(reader=global_pass):
 first=reader();second=reader()
 if first!=second:raise SystemExit("FAIL: global specialized snapshot changed between global passes")
 return sum(len(x[3]) for x in first)
if sys.argv[1:]==['--self-test']:
 calls=0
 def changed():
  global calls
  calls+=1
  return [('first',b'old' if calls==1 else b'new',{})]
 try:verify(changed)
 except SystemExit:print('PASS: global snapshot rejects mutation of an early set between global passes')
 else:raise AssertionError('global snapshot accepted hybrid generations')
elif not sys.argv[1:]:print(f"PASS: global specialized snapshot verified {verify()} files")
else:raise SystemExit('usage: check-specialized-manifest-snapshot.py [--self-test]')
