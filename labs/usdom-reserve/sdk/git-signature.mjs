const openPgpFingerprint=/^[0-9A-F]{40}(?:[0-9A-F]{24})?$/;
const sshFingerprint=/^SHA256:[A-Za-z0-9+/]{43}$/;
const releaseTag=/^usdom-v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$/;

export function isCanonicalGitSigningKeyFingerprint(value) {
 return typeof value==='string' && (openPgpFingerprint.test(value) || sshFingerprint.test(value));
}

export function isCanonicalReleaseTag(value) {
 return typeof value==='string' && releaseTag.test(value);
}

export function parseGitSignatureFingerprint(output) {
 if(typeof output!=='string') return null;
 for(const line of output.split(/\r?\n/)) {
  const gpg=line.match(/^\[GNUPG:\] VALIDSIG (.+)$/);
  if(gpg) {
   const fields=gpg[1].trim().split(/\s+/);
   const primary=fields.at(-1);
   if(openPgpFingerprint.test(primary??'')) return primary;
   if(openPgpFingerprint.test(fields[0]??'')) return fields[0];
  }
  const ssh=line.match(/^Good "git" signature for .+ with [A-Za-z0-9-]+ key (SHA256:[A-Za-z0-9+/]{43})$/);
  if(ssh) return ssh[1];
 }
 return null;
}
