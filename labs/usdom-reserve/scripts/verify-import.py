"""Read-only check of the initial import and explicitly recorded local changes."""
from pathlib import Path
import hashlib,json
root=Path(__file__).resolve().parents[1]
p=json.loads((root/'PROVENANCE.json').read_text())
changes=json.loads((root/'LOCAL-CHANGES.json').read_text())['modified_imported_files']
assert set(changes).issubset(p['imported_files_sha256'])
for name,digest in p['imported_files_sha256'].items():
 path=(root/name).resolve()
 assert path.is_relative_to(root),name
 if name in changes:
  change=changes[name]
  assert change['original_sha256']==digest,name
  assert change['reason'],name
  digest=change['current_sha256']
 assert hashlib.sha256(path.read_bytes()).hexdigest()==digest,name
assert p['production_ready'] is False
assert p['implementation_repository']=='https://github.com/sorenplanck/dom-protocol'
print(f"PASS: {len(p['imported_files_sha256'])} imported files checked, including {len(changes)} explicitly recorded modifications; production readiness remains false")
