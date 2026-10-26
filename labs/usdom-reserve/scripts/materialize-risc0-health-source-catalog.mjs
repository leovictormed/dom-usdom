import {writeReleaseFailure} from '../sdk/pilot-safe-diagnostics.mjs';
import {lstat,mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readDirectFile} from '../sdk/direct-project-file.mjs';
import {writePrivateFileDurable,writePrivateFileDurableNew} from '../sdk/durable-private-file.mjs';
import {
  prepareRiscZeroHealthSourceCatalogMaterialization,
  RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH,
} from '../sdk/risc0-health-source-catalog-materialization.mjs';
import {parseStrictJson} from '../sdk/strict-json.mjs';
import {captureRiscZeroHealthCatalogInputs} from '../sdk/risc0-health-catalog-input-snapshot.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const sourcePath='config/risc0-health-sources.unconfigured.json';
const metadataPath='config/mainnet-release-evidence.unconfigured.json';

async function assertWritableTarget(relative) {
  const target=path.join(root,relative);
  try {
    const status=await lstat(target);
    if(!status.isFile() || status.isSymbolicLink()) throw new Error(`${relative} is not a direct regular file`);
  } catch(error) {
    if(error.code!=='ENOENT') throw error;
  }
  return target;
}

async function atomicWrite(relative,content) {
  const target=await assertWritableTarget(relative);
  await mkdir(path.dirname(target),{recursive:true,mode:0o700});
  await writePrivateFileDurable(target,content);
}

async function immutableWrite(relative,content) {
  const target=await assertWritableTarget(relative),bytes=Buffer.from(content);
  await mkdir(path.dirname(target),{recursive:true,mode:0o700});
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
    try {
      const result=prepareRiscZeroHealthSourceCatalogMaterialization({
        catalog:parseStrictJson(snapshot.catalog.toString('utf8'),{label:sourcePath}),
        evidence:parseStrictJson(snapshot.evidence.toString('utf8'),{label:metadataPath}),
      });
      await snapshot.assertOriginsUnchanged();
      await immutableWrite(RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH,result.catalogContent);
      await snapshot.assertOriginsUnchanged();
      await atomicWrite(metadataPath,result.evidenceContent);
      await snapshot.assertOriginsUnchanged();
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
      console.log(JSON.stringify({ok:true,path:RISC0_HEALTH_SOURCE_CATALOG_EVIDENCE_PATH,
        sha256:result.sha256,catalogHash:result.catalog.catalogHash,sourceCount:result.catalog.sources.length},null,2));
    } finally { await snapshot.cleanup(); }
  } catch(error) {
    writeReleaseFailure('materialize-risc0-health-source-catalog',error);
    process.exitCode=1;
  }
}
