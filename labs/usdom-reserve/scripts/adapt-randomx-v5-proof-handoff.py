#!/usr/bin/env python3
"""Read-only adapter from the active RandomX v5 runner to a rebuild handoff recipe."""

from __future__ import annotations

import argparse, hashlib, json, os, re, sys
from pathlib import Path

H64=re.compile(r"^[0-9a-f]{64}$")

def fail(message): raise ValueError(message)
def digest(data): return hashlib.sha256(data).hexdigest()
def exact(value, fields, label):
    if not isinstance(value,dict) or set(value)!=set(fields): fail(f"{label} schema differs")
    return value
def capture(path, root, label, maximum=300*1024*1024):
    resolved=path.resolve(strict=True)
    if resolved!=root and root not in resolved.parents: fail(f"{label} escapes its root")
    stat=path.lstat()
    if path.is_symlink() or not path.is_file() or stat.st_nlink!=1 or stat.st_size>maximum: fail(f"{label} is not a bounded direct file")
    data=path.read_bytes(); return data,digest(data)
def parsed(path,root,label):
    data,sha=capture(path,root,label,2*1024*1024); return json.loads(data),sha
def process_matches(pid, runner):
    try:
        raw=Path(f"/proc/{pid}/cmdline").read_bytes()
        return raw == f"bash\0{runner}\0".encode()
    except (FileNotFoundError,PermissionError,ProcessLookupError): return False

def inspect(args):
    for field in ('expected_runner_sha256','expected_current_cargo_lock_sha256','expected_current_source_graph_sha256'):
        if not H64.fullmatch(getattr(args,field)): fail(f'{field} must be one canonical SHA-256')
    run=Path(args.run_directory).resolve(strict=True); lab=Path(args.lab_root).resolve(strict=True)
    runner=run/'runner-v5.sh'; runner_bytes,runner_sha=capture(runner,run,'runner',64*1024)
    if runner_sha!=args.expected_runner_sha256: fail('runner differs from its reviewed SHA-256')
    build,build_sha=parsed(run/'build-status.json',run,'build status')
    exact(build,['schema','status','startedAt','finishedAt','exitCode','sourceGraphSha256','cargoLockSha256','recursionArtifactSha256','binarySha256'],'build status')
    if build['schema']!='usdom-randomx-proof-build-v1' or build['status']!='succeeded' or build['exitCode']!=0: fail('build status is not successful')
    if any(not H64.fullmatch(str(build[x])) for x in ('sourceGraphSha256','cargoLockSha256','recursionArtifactSha256','binarySha256')): fail('build hashes are malformed')
    status,status_sha=parsed(run/'status.json',run,'run status')
    base=['schema','status','pid','startedAt','exitCode','jobIndexSha256','elfSha256','iidFileSha256','programBinarySha256','recursionArtifactSha256','proverBinarySha256','sourceGraphSha256','jobCount','command']
    if status.get('status')=='running': exact(status,base,'run status')
    else: exact(status,base+['finishedAt'],'run status')
    if status['schema']!='usdom-local-randomx-proof-run-v5' or not isinstance(status['pid'],int) or status['pid']<=1 or status['jobCount']!=2: fail('run identity is invalid')
    for field in ('jobIndexSha256','elfSha256','iidFileSha256','programBinarySha256','recursionArtifactSha256','proverBinarySha256','sourceGraphSha256'):
        if not H64.fullmatch(str(status[field])): fail(f'{field} is malformed')
    if status['recursionArtifactSha256']!=build['recursionArtifactSha256'] or status['proverBinarySha256']!=build['binarySha256'] or status['sourceGraphSha256']!=build['sourceGraphSha256']: fail('run differs from authenticated build')
    job_path=lab/'evidence/randomx-proof-jobs/randomx-proof-job-index.json'
    job,job_sha=parsed(job_path,lab,'job index')
    if job_sha!=status['jobIndexSha256'] or job.get('schema')!='usdom-randomx-proof-job-set-v1' or job.get('job_count')!=2 or len(job.get('jobs',[]))!=2: fail('job index differs from the run')
    if job.get('randomx_user_elf_sha256')!=status['elfSha256'] or job.get('randomx_program_sha256')!=status['programBinarySha256'] or job.get('randomx_image_id_file_sha256')!=status['iidFileSha256']: fail('job artifacts differ from run')
    binding=digest(bytes.fromhex(build_sha)+bytes.fromhex(runner_sha)+bytes.fromhex(job_sha))
    live=process_matches(status['pid'],str(runner))
    if status['status']=='running':
        if not live: fail('running status has no matching live runner process')
        return {'schema':'usdom-long-proof-handoff-v1','classification':'active','releaseAllowed':False,'promotionAllowed':False,'runManifestSha256':binding,'proofSchema':'usdom-randomx-receipt-set-v1','reason':'authenticated RandomX v5 runner is active'}
    if live: fail('terminal status exists while matching runner is active')
    if status['status'] not in ('succeeded','failed') or status['exitCode']<0 or status['exitCode']>255: fail('terminal status is invalid')
    succeeded=status['status']=='succeeded' and status['exitCode']==0
    if succeeded:
        index_path=lab/'evidence/randomx-receipt-set/randomx-receipt-set-index.json'
        index,index_sha=parsed(index_path,lab,'receipt index')
        required=['schema','proof_job_index_path','proof_job_index_sha256','manifest_sha256','randomx_receipt_image_id','randomx_user_elf_sha256','risc0_zkvm_version','receipt_kind','previous_height','target_height','confirmation_height','segment_count','receipt_count','randomx_relations_executed','receipts_verified','dev_mode','generates_proofs','mines','receipts']
        exact(index,required,'receipt index')
        receipts=index['receipts']
        if index['schema']!='usdom-randomx-receipt-set-v1' or index['proof_job_index_sha256']!=job_sha or index['receipt_count']!=2 or not isinstance(receipts,list) or len(receipts)!=2 or index['receipts_verified'] is not True or index['dev_mode'] is not False or index['generates_proofs'] is not True or index['mines'] is not False: fail('receipt index is not a verified real proof set')
        seen=set()
        for position,item in enumerate(receipts):
            exact(item,['index','segment_index','block_index','block_height','statement_sha256','expected_journal','receipt_file','receipt_sha256','receipt_bytes'],f'receipt {position}')
            if item['index']!=position or item['receipt_file'] in seen or not H64.fullmatch(str(item['receipt_sha256'])): fail('receipt identity is invalid')
            seen.add(item['receipt_file']); data,sha=capture(index_path.parent/item['receipt_file'],index_path.parent,f'receipt {position}')
            if sha!=item['receipt_sha256'] or len(data)!=item['receipt_bytes']: fail('receipt content differs from index')
        terminal_sha=digest(bytes.fromhex(status_sha)+bytes.fromhex(index_sha))
    else:
        if status['status']=='failed' and status['exitCode']==0: fail('failed status cannot have zero exit')
        terminal_sha=status_sha
    current=(build['cargoLockSha256']==args.expected_current_cargo_lock_sha256
             and build['sourceGraphSha256']==args.expected_current_source_graph_sha256
             and args.expected_current_proof_schema=='usdom-randomx-receipt-set-v1')
    classification='current-complete' if succeeded and current else 'historical-stale' if succeeded else 'failed-stale'
    return {'schema':'usdom-long-proof-handoff-v1','classification':classification,'releaseAllowed':True,'promotionAllowed':classification=='current-complete','runManifestSha256':binding,'terminalSha256':terminal_sha,'proofSchema':'usdom-randomx-receipt-set-v1','reason':'authenticated RandomX v5 terminal result; promotion follows source classification'}

def main():
    p=argparse.ArgumentParser(); p.add_argument('--run-directory',required=True); p.add_argument('--lab-root',required=True); p.add_argument('--expected-runner-sha256',required=True); p.add_argument('--expected-current-cargo-lock-sha256',required=True); p.add_argument('--expected-current-source-graph-sha256',required=True); p.add_argument('--expected-current-proof-schema',required=True); p.add_argument('--recipe'); a=p.parse_args()
    try:
        result=inspect(a); encoded=json.dumps(result,indent=2,sort_keys=True)+'\n'
        if a.recipe:
            target=Path(a.recipe)
            if target.exists() or target.is_symlink(): fail('handoff recipe already exists')
            temp=target.with_name(f'.{target.name}.{os.getpid()}.tmp'); temp.write_text(encoded); os.replace(temp,target)
        print(encoded,end=''); return 0
    except (ValueError,OSError,json.JSONDecodeError) as error:
        print(f'RandomX v5 handoff refused: {error}',file=sys.stderr); return 1
if __name__=='__main__': raise SystemExit(main())
