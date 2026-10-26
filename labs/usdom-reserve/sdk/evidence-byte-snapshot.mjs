export async function assertEvidenceByteSnapshotsUnchanged(snapshots,readFile,{label='evidence'}={}) {
  if(!(snapshots instanceof Map) || typeof readFile!=='function') {
    throw new Error('evidence snapshot recheck inputs are invalid');
  }
  for(const [relative,expected] of snapshots) {
    if(typeof relative!=='string' || !Buffer.isBuffer(expected)) {
      throw new Error('evidence snapshot entry is invalid');
    }
    const observed=await readFile(relative);
    if(!Buffer.isBuffer(observed) || !observed.equals(expected)) {
      throw new Error(`${label} changed during readiness assessment: ${relative}`);
    }
  }
}
