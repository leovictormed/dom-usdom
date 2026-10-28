#!/bin/bash
set -euo pipefail
set +x
umask 077
export LC_ALL=C LANG=C
unset BASH_ENV ENV CDPATH PYTHONPATH PYTHONHOME NODE_OPTIONS LD_PRELOAD LD_LIBRARY_PATH

if [[ "$#" -ne 1 || "$1" != pre-ceremony && "$1" != post-ceremony ]]; then
  echo 'usage: execute-usdom-release-validation-jobs.sh pre-ceremony|post-ceremony' >&2
  exit 64
fi
mode="$1"
if [[ "${USDOM_RUN_LONG_RELEASE_TEST-}" != YES ]]; then
  echo 'refusing: set USDOM_RUN_LONG_RELEASE_TEST=YES to execute the three supervised release vectors' >&2
  exit 64
fi
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
project="$repo/labs/usdom-reserve"
evidence="$project/config/mainnet-release-evidence.unconfigured.json"
report="$project/evidence/release-validation-report.json"
jobs="${HOME}/.config/usdom-proof/jobs"
state="${HOME}/.local/state/usdom-proof"
job_set="${USDOM_CONTROL_EVIDENCE_DIRECTORY:-/home/leonardov/usdom-mainnet-private/control-plane}/release-validation-job-set.json"

mapfile -t identity < <(/usr/bin/python3 - "$evidence" <<'PY'
import json,os,re,stat,sys
def pairs(items):
 value={}
 for key,item in items:
  if key in value: raise ValueError('duplicate evidence key')
  value[key]=item
 return value
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW); before=os.fstat(fd)
try:
 if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>4*1024*1024: raise SystemExit('unsafe release evidence')
 raw=os.read(fd,before.st_size+1); after=os.fstat(fd)
finally: os.close(fd)
if len(raw)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns): raise SystemExit('unstable release evidence')
value=json.loads(raw,object_pairs_hook=pairs)
fields=[value.get(k) for k in ('releaseId','sourceCommit','sourceTag')]
if not isinstance(fields[0],str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}',fields[0]): raise SystemExit('invalid releaseId')
if not isinstance(fields[1],str) or not re.fullmatch(r'[0-9a-f]{40}',fields[1]): raise SystemExit('invalid sourceCommit')
if not isinstance(fields[2],str) or not re.fullmatch(r'usdom-v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?',fields[2]): raise SystemExit('invalid sourceTag')
print(*fields,sep='\n')
PY
)
test "${#identity[@]}" -eq 3
/usr/bin/python3 "$project/scripts/install-supervised-proof-user-service.py" --repository "$repo" >/dev/null
if [[ "$mode" == pre-ceremony ]]; then
 prepared="$($project/scripts/prepare-usdom-release-validation-jobs.sh "${identity[0]}" "${identity[1]}" "${identity[2]}")"
else
 prepared="$(/usr/bin/python3 - "$job_set" "${identity[0]}" "${identity[1]}" "${identity[2]}" <<'PY'
import json,os,re,stat,sys
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW); before=os.fstat(fd)
try: raw=os.read(fd,65537); after=os.fstat(fd)
finally: os.close(fd)
if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_mode&0o077 or len(raw)!=before.st_size or before.st_size>65536 or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns): raise SystemExit('unsafe release-vector job set')
value=json.loads(raw)
if set(value)!={'schema','releaseId','sourceCommit','sourceTag','checkpointRunId','randomxRunId','nativePrivacyRunId'} or value['schema']!='usdom-release-validation-job-set/v1' or [value['releaseId'],value['sourceCommit'],value['sourceTag']]!=sys.argv[2:]: raise SystemExit('release-vector job set identity mismatch')
for key in ('checkpointRunId','randomxRunId','nativePrivacyRunId'):
 if not isinstance(value[key],str) or not re.fullmatch(r'[0-9a-f]{64}',value[key]): raise SystemExit('invalid release-vector run ID')
print(f"checkpointRunId={value['checkpointRunId']}")
print(f"randomxRunId={value['randomxRunId']}")
print(f"nativePrivacyRunId={value['nativePrivacyRunId']}")
PY
)"
fi
mapfile -t lines <<<"$prepared"
test "${#lines[@]}" -eq 3
declare -a ids=()
for index in 0 1 2; do
  expected=(checkpointRunId randomxRunId nativePrivacyRunId)
  [[ "${lines[$index]}" =~ ^${expected[$index]}=([0-9a-f]{64})$ ]] || { echo 'invalid prepared release-vector identity output' >&2; exit 125; }
  ids+=("${BASH_REMATCH[1]}")
done
test "${ids[0]}" != "${ids[1]}" -a "${ids[0]}" != "${ids[2]}" -a "${ids[1]}" != "${ids[2]}"

if [[ "$mode" == pre-ceremony ]]; then selected=("${ids[0]}" "${ids[1]}"); else selected=("${ids[2]}"); fi
for run_id in "${selected[@]}"; do
  unit="usdom-proof@${run_id}.service"
  /usr/bin/systemctl --user start "$unit"
  while /usr/bin/systemctl --user --quiet is-active "$unit"; do /usr/bin/sleep 10; done
  test "$(/usr/bin/systemctl --user show "$unit" --property=Result --value)" = success
  /usr/bin/python3 "$project/scripts/control-supervised-long-proof.py" status \
    --state-root "$state" --run-id "$run_id" \
    | /usr/bin/python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["terminalAuthenticated"] and not v["activeProcessAuthenticated"]'
done

if [[ "$mode" == pre-ceremony ]]; then
 cd "$project"
 /usr/bin/python3 - "${identity[@]}" "${ids[@]}" <<'PY' \
   | node scripts/install-private-file-immutable-stdin.mjs --json "$job_set"
import json,sys
release,commit,tag,checkpoint,randomx,privacy=sys.argv[1:]
print(json.dumps({'schema':'usdom-release-validation-job-set/v1','releaseId':release,
 'sourceCommit':commit,'sourceTag':tag,'checkpointRunId':checkpoint,
 'randomxRunId':randomx,'nativePrivacyRunId':privacy},sort_keys=True,separators=(',',':')))
PY
 exit 0
fi

/usr/bin/python3 "$project/scripts/materialize-usdom-release-validation-report.py" \
  --repository "$repo" --jobs-directory "$jobs" --state-root "$state" \
  --release-evidence "$evidence" --output "$report" \
  --checkpoint390-run-id "${ids[0]}" --randomxCache-run-id "${ids[1]}" \
  --nativePrivacy-run-id "${ids[2]}"
cd "$project"
npm run --silent materialize:release-validation-evidence
