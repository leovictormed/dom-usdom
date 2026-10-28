export function requireReleaseArtifact(evidence,key,path,actualSha256) {
  const value=evidence?.[key];
  if(!value||Object.keys(value).sort().join(',')!=='path,sha256'||value.path!==path
      ||!/^([0-9a-f]{64})$/.test(value.sha256??'')||value.sha256!==actualSha256) {
    throw new Error(`${key} does not hash-address the current canonical artifact`);
  }
  return true;
}
