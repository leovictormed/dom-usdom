#!/usr/bin/env python3
"""Materialize a V3 manifest only from an authenticated complete local recipe."""
import argparse, hashlib, json, os, stat, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from rebuild_v3_build_policy import load_policy,strict_json,verify_attestation
from durable_create_once import install_create_once
H64=__import__('re').compile(r'[0-9a-f]{64}')
MAX=4*1024*1024
def fail(x): raise ValueError(x)
def capture(path,label,executable=False):
 m=path.stat(follow_symlinks=False)
 if not stat.S_ISREG(m.st_mode) or m.st_nlink!=1 or m.st_uid!=os.getuid() or m.st_mode&0o022 or m.st_size<=0 or m.st_size>MAX or (executable and not os.access(path,os.X_OK)): fail(f'{label} is not an authenticated direct executable/file')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  opened=os.fstat(fd); data=b''
  while len(data)<=MAX:
   chunk=os.read(fd,min(1024*1024,MAX+1-len(data)))
   if not chunk: break
   data+=chunk
  after=os.fstat(fd)
 finally: os.close(fd)
 identity=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_nlink,x.st_mtime_ns,x.st_ctime_ns)
 if identity(m)!=identity(opened) or identity(opened)!=identity(after) or len(data)!=m.st_size: fail(f'{label} changed while reading')
 return data,hashlib.sha256(data).hexdigest()
def pin(path,expected,label):
 path=path.resolve(strict=True); data,actual=capture(path,label,True)
 if not H64.fullmatch(expected or '') or actual!=expected: fail(f'{label} hash differs from its reviewed pin')
 return str(path),actual,len(data)
def main():
 p=argparse.ArgumentParser(); p.add_argument('--recipe',type=Path,required=True); p.add_argument('--expected-recipe-sha256',required=True); p.add_argument('--receipt-verifier',type=Path,required=True); p.add_argument('--expected-receipt-verifier-sha256',required=True); p.add_argument('--receipt-verifier-build-policy',type=Path,required=True); p.add_argument('--expected-receipt-verifier-build-policy-sha256',required=True); p.add_argument('--receipt-verifier-build-attestation',type=Path,required=True); p.add_argument('--expected-receipt-verifier-build-attestation-sha256',required=True); p.add_argument('--aggregator',type=Path,required=True); p.add_argument('--expected-aggregator-sha256',required=True); p.add_argument('--output',type=Path,required=True); a=p.parse_args()
 raw,recipe_sha=capture(a.recipe,'recipe')
 if recipe_sha!=a.expected_recipe_sha256: fail('recipe differs from its reviewed SHA-256')
 recipe=strict_json(raw.decode())
 if set(recipe)!={'schema','realProofsVerified','manifest','receiptVerifications','receiptVerifierBuild'} or recipe['schema']!='usdom-checkpoint-rebuild-v3-materialization-recipe-v2': fail('recipe schema is invalid')
 if recipe['realProofsVerified'] is not True or not recipe['receiptVerifications']: fail('real receipt/proof evidence is incomplete; production manifest refused')
 verifier,verifier_sha,verifier_size=pin(a.receipt_verifier,a.expected_receipt_verifier_sha256,'receipt verifier')
 policy_raw,policy_sha=capture(a.receipt_verifier_build_policy,'receipt verifier build policy');attestation_raw,attestation_sha=capture(a.receipt_verifier_build_attestation,'receipt verifier build attestation')
 if policy_sha!=a.expected_receipt_verifier_build_policy_sha256 or attestation_sha!=a.expected_receipt_verifier_build_attestation_sha256: fail('receipt verifier build evidence differs from reviewed pin')
 policy=load_policy(policy_raw.decode());attestation=verify_attestation(attestation_raw.decode(),policy,policy_sha,verifier_sha,verifier_size)
 build=recipe['receiptVerifierBuild'];build_keys={'binarySha256','policySha256','attestationSha256','sourceClosureSha256','buildInputCommitment'}
 if not isinstance(build,dict) or set(build)!=build_keys or any(not H64.fullmatch(build.get(key) or '') for key in build_keys): fail('recipe receipt verifier build binding is invalid')
 if build!={'binarySha256':verifier_sha,'policySha256':policy_sha,'attestationSha256':attestation_sha,'sourceClosureSha256':policy['sourceClosureSha256'],'buildInputCommitment':attestation['buildInputCommitment']}: fail('recipe receipt verifier build binding differs from authenticated evidence')
 aggregator,aggregator_sha,_=pin(a.aggregator,a.expected_aggregator_sha256,'receipt aggregator')
 manifest=recipe['manifest']; stages=manifest.get('stages',[])
 order=['segment','pin-segment','outer','pin-outer','finalized-burn','pin-finalized-burn','receipts','gate']
 if [x.get('name') for x in stages]!=order: fail('manifest stage graph is incomplete or out of order')
 for stage in stages:
  if not stage.get('argv') or not stage.get('outputs') or not stage.get('verification') or any('PLACEHOLDER' in str(x) for x in stage.get('argv',[])): fail(f"stage {stage.get('name')} contains an unmaterialized command")
 receipts=[x for x in stages if x.get('name')=='receipts']
 if len(receipts)!=1: fail('manifest must contain exactly one receipts stage')
 stage=receipts[0]
 if stage.get('verificationSteps') not in ([],None): fail('recipe must not predeclare receipt verification commands')
 steps=[]
 for number,item in enumerate(recipe['receiptVerifications']):
  keys={'receipt','receiptSha256','imageId','journal','predecessor','predecessorSha256','verification'}
  if not isinstance(item,dict) or set(item)!=keys or not all(H64.fullmatch(item[x] or '') for x in ('receiptSha256','imageId','journal','predecessorSha256')): fail(f'receipt verification {number} schema is invalid')
  steps.append({'argv':[verifier,item['receipt'],item['receiptSha256'],item['imageId'],item['journal'],item['predecessor'],item['predecessorSha256'],item['verification']], 'outputs':[item['verification']]})
 stage['verificationSteps']=steps
 verification=stage.get('verification')
 index=stage['inputs'][0] if len(stage.get('inputs',[]))==1 else fail('receipts stage must consume one authenticated aggregation index')
 stage['verificationArgv']=[aggregator,index,verification]
 tools=manifest.get('tools');
 if not isinstance(tools,list): fail('manifest tools are invalid')
 tools[:]=[x for x in tools if x.get('path') not in (verifier,aggregator)]+[{'path':verifier,'sha256':verifier_sha},{'path':aggregator,'sha256':aggregator_sha}]
 encoded=(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode()
 install_create_once(Path(os.path.abspath(a.output)),encoded,mode=0o600,maximum=MAX,
                     private_parent=True,allow_equal=True)
 print(hashlib.sha256(encoded).hexdigest()); return 0
if __name__=='__main__':
 try: raise SystemExit(main())
 except (OSError,ValueError,KeyError,json.JSONDecodeError) as e: print(f'V3 manifest materialization failed: {e}',file=sys.stderr); raise SystemExit(1)
