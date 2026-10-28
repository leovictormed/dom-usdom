import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {createHash} from 'node:crypto';
import {lstat,mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
import {durableReplacementFailureExitCode,replaceLockedParentFileDurable}
  from '../sdk/durable-locked-parent-replacement.mjs';
import {
  prepareRiscZeroHealthSourceCatalogMaterialization,
  RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH,
} from '../sdk/risc0-health-source-catalog-materialization.mjs';
import {parseStrictJsonBytes} from '../sdk/strict-json.mjs';
import {captureRiscZeroHealthCatalogInputs} from '../sdk/risc0-health-catalog-input-snapshot.mjs';
import {snapshotExecutable} from '../sdk/stable-executable.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const currentUid=process.getuid();
const sourcePath='config/risc0-health-sources.unconfigured.json';
const metadataPath='config/mainnet-release-evidence.unconfigured.json';
const pythonExecutable=await snapshotExecutable('python3');
const sha256=value=>createHash('sha256').update(value).digest('hex');
process.umask(0o077);

async function ensureDirectParent(relative) {
  if(typeof relative!=='string' || relative==='' || relative.startsWith('/')
      || relative.includes('\\')
      || relative.split('/').some(part=>part==='' || part==='.' || part==='..')) {
    throw new Error('RISC Zero health materialization path is not canonical');
  }
  let current=root;
  for(const component of path.dirname(relative).split('/')) {
    current=path.join(current,component);
    try { await mkdir(current,{mode:0o700}); }
    catch(error) { if(error?.code!=='EEXIST') throw error; }
    const metadata=await lstat(current);
    if(!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.uid!==currentUid) {
      throw new Error(`unsafe RISC Zero health materialization directory: ${current}`);
    }
  }
}

async function assertWritableTarget(relative) {
  await ensureDirectParent(relative);
  const target=path.join(root,relative);
  try {
    const status=await lstat(target);
    if(!status.isFile() || status.isSymbolicLink()) throw new Error(`${relative} is not a direct regular file`);
  } catch(error) {
    if(error.code!=='ENOENT') throw error;
  }
  return target;
}

async function compareAndSwapEvidence(relative,content,previousBytes) {
  const target=await assertWritableTarget(relative);
  const parent=path.dirname(target),metadata=await lstat(parent),bytes=Buffer.from(content);
  if(!metadata.isDirectory()||metadata.isSymbolicLink()||metadata.uid!==currentUid
      ||(metadata.mode&0o022)!==0) throw new Error('RISC Zero evidence parent is unsafe');
  await replaceLockedParentFileDurable({target,contents:bytes,expectedSha256:sha256(bytes),
    expectedPreviousSha256:sha256(previousBytes),expectedParentDevice:String(metadata.dev),
    expectedParentInode:String(metadata.ino),metadataInspectorExecutable:pythonExecutable.path,
    metadataInspectorSha256:pythonExecutable.sha256,expectedMode:0o600});
}

async function immutableWrite(relative,content) {
  const target=await assertWritableTarget(relative),bytes=Buffer.from(content);
  try { await writePrivateFileDurableNew(target,bytes); }
  catch(error) {
    if(error?.message!=='durable target already exists') throw error;
    const existing=await readDirectFile(target,{minimum:bytes.length,maximum:bytes.length,
      privateMode:true,label:'immutable RISC Zero health source catalog'});
    if(!existing.equals(bytes)) throw new Error('immutable RISC Zero health source catalog differs');
  }
}

if(process.argv.length!==2) {
  console.error('Usage: npm run materialize:risc0-health-source-catalog');
  process.exitCode=2;
} else {
  try {
    const snapshot=await captureRiscZeroHealthCatalogInputs({
      catalog:path.join(root,sourcePath),evidence:path.join(root,metadataPath),
    });
    let primaryError=null,successRecord=null;
    try {
      const result=prepareRiscZeroHealthSourceCatalogMaterialization({
        catalog:parseStrictJsonBytes(snapshot.catalog,{label:sourcePath}),
        evidence:parseStrictJsonBytes(snapshot.evidence,{label:metadataPath}),
      });
      await snapshot.assertOriginsUnchanged();
      await immutableWrite(RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH,result.catalogContent);
      await snapshot.assertOriginsUnchanged();
      await compareAndSwapEvidence(metadataPath,result.evidenceContent,snapshot.evidence);
      await snapshot.assertOriginsEqual({catalog:snapshot.catalog,
        evidence:Buffer.from(result.evidenceContent)});
      const [installedCatalog,installedEvidence]=await Promise.all([
        readDirectFile(path.join(root,RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH),{
          minimum:Buffer.byteLength(result.catalogContent),
          maximum:Buffer.byteLength(result.catalogContent),privateMode:true,
          label:'installed immutable RISC Zero health source catalog',
        }),
        readDirectFile(path.join(root,metadataPath),{
          minimum:Buffer.byteLength(result.evidenceContent),
          maximum:Buffer.byteLength(result.evidenceContent),privateMode:true,
          label:'installed RISC Zero health release evidence',
        }),
      ]);
      if(!installedCatalog.equals(Buffer.from(result.catalogContent))
          ||!installedEvidence.equals(Buffer.from(result.evidenceContent))) {
        throw new Error('installed RISC Zero health generation differs from prepared bytes');
      }
      successRecord={ok:true,path:RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH,
        sha256:result.sha256,catalogHash:result.catalog.catalogHash,
        sourceCount:result.catalog.sources.length};
    } catch(error) {
      primaryError=error;
      throw error;
    } finally {
      try { await snapshot.cleanup(); }
      catch(cleanupError) { if(primaryError===null) throw cleanupError; }
    }
    console.log(JSON.stringify(successRecord,null,2));
  } catch(error) {
    writeReleaseFailure('materialize-risc0-health-source-catalog',error);
    process.exitCode=durableReplacementFailureExitCode(error);
  }
}
