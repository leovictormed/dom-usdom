#!/usr/bin/env python3
"""Aggregate independently verified RISC Zero receipts into one V3 stage record."""
import hashlib, json, os, stat, sys
from pathlib import Path

H64 = __import__('re').compile(r"[0-9a-f]{64}")
MAX_JSON = 4 * 1024 * 1024

def fail(message): raise ValueError(message)
def capture(path, label):
    before=path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size<=0 or before.st_size>MAX_JSON:
        fail(f"{label} is not a bounded direct single-link file")
    with path.open('rb') as stream:
        opened=os.fstat(stream.fileno()); data=stream.read(MAX_JSON+1); after=os.fstat(stream.fileno())
    identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_nlink,value.st_mtime_ns,value.st_ctime_ns)
    if identity(before)!=identity(opened) or identity(opened)!=identity(after) or len(data)!=before.st_size:
        fail(f"{label} changed while reading")
    return data
def parsed(path,label):
    data=capture(path,label)
    try: value=json.loads(data.decode('utf-8'))
    except Exception as error: fail(f"invalid {label}: {error}")
    return value,hashlib.sha256(data).hexdigest()
def exact(value,keys,label):
    if not isinstance(value,dict) or set(value)!=set(keys): fail(f"{label} schema is invalid")
    return value
def environment(name):
    try: value=json.loads(os.environ[name])
    except Exception: fail(f"{name} is invalid")
    if not isinstance(value,dict) or any(not isinstance(k,str) or not H64.fullmatch(v or '') for k,v in value.items()):
        fail(f"{name} is invalid")
    return value

def main():
    if len(sys.argv)!=3: fail('usage: aggregator INDEX OUTPUT_RECORD')
    inputs=environment('USDOM_AUTHENTICATED_STAGE_INPUTS'); outputs=environment('USDOM_AUTHENTICATED_STAGE_OUTPUTS')
    index_path=Path(sys.argv[1]); record_path=Path(sys.argv[2])
    index,index_sha=parsed(index_path,'receipt aggregation index')
    if inputs.get(str(index_path))!=index_sha and inputs.get(sys.argv[1])!=index_sha:
        fail('aggregation index is not an authenticated stage input')
    exact(index,['schema','predecessorSha256','receipts'],'receipt aggregation index')
    if index['schema']!='usdom-rebuild-receipt-aggregation-v1' or not H64.fullmatch(index['predecessorSha256'] or '') or not index['receipts']:
        fail('receipt aggregation identity is invalid')
    predecessor=index['predecessorSha256']; seen_paths=set(); seen_hashes=set()
    for number,item in enumerate(index['receipts']):
        exact(item,['receipt','verification','programVerification','programVerificationSha256'],'receipt entry')
        receipt=item['receipt']; verification=item['verification']; program=item['programVerification']
        if receipt in seen_paths or verification in seen_paths: fail('receipt paths are not unique')
        seen_paths.update((receipt,verification))
        receipt_bytes=capture(Path(receipt),f'receipt {number}'); receipt_sha=hashlib.sha256(receipt_bytes).hexdigest()
        if outputs.get(receipt)!=receipt_sha: fail('receipt is not an authenticated stage output')
        verified,verified_sha=parsed(Path(verification),f'receipt verification {number}')
        if outputs.get(verification)!=verified_sha: fail('receipt verification is not an authenticated stage output')
        exact(verified,['schema','receiptSha256','receiptBytes','methodImageId','journal','predecessorSha256','cryptographicallyVerified'],'receipt verification')
        if verified['schema']!='usdom-rebuild-receipt-verification-v1' or verified['cryptographicallyVerified'] is not True or verified['receiptSha256']!=receipt_sha or verified['receiptBytes']!=len(receipt_bytes) or verified['predecessorSha256']!=predecessor:
            fail('receipt verification does not bind the exact chain')
        prior,prior_sha=parsed(Path(program),f'program verification {number}')
        if prior_sha!=item['programVerificationSha256'] or not H64.fullmatch(prior_sha):
            fail('ProgramBinary verification differs from its authenticated index hash')
        exact(prior,['schema','imageId','journal','programBinarySha256'],'program verification')
        if prior['schema']!='usdom-rebuild-program-verification-v1' or not all(H64.fullmatch(prior[x] or '') for x in ['imageId','journal','programBinarySha256']) or verified['methodImageId']!=prior['imageId'] or verified['journal']!=prior['journal']:
            fail('receipt method/journal differs from ProgramBinary verification')
        if receipt_sha in seen_hashes: fail('duplicate receipt content')
        seen_hashes.add(receipt_sha); predecessor=verified_sha
    expected=set(seen_paths)
    if set(outputs)!=expected: fail('receipt stage outputs are incomplete or contain extras')
    record={'schema':'usdom-rebuild-stage-verification-v1','stage':'receipts','inputs':inputs,'outputs':outputs,'claims':{
      'receiptsCryptographicallyVerified':True,'methodImageIdsMatched':True,'journalDigestsMatched':True,'elfReceiptPairsMatched':True}}
    encoded=(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n').encode()
    descriptor=os.open(record_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'wb') as stream: stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
    parent=os.open(record_path.parent or Path('.'),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(parent)
    finally: os.close(parent)
    return 0
if __name__=='__main__':
    try: raise SystemExit(main())
    except (OSError,ValueError) as error:
        print(f'receipt aggregation failed: {error}',file=sys.stderr); raise SystemExit(1)
