import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,cpSync,existsSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync,
} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import os from 'node:os';
import path from 'node:path';

const projectRoot=fileURLToPath(new URL('../..',import.meta.url));
const nodeBin=path.dirname(process.execPath);
const sha256=value=>createHash('sha256').update(value).digest('hex');

function command(name,args,options={}) {
  const result=spawnSync(name,args,{encoding:'utf8',...options});
  assert.equal(result.status,0,`${name}: ${result.stderr}\n${result.stdout}`);
  return result.stdout.trim();
}
function accountHomeEnvironment(temporary,home,extra={}) {
  const binaries=path.join(temporary,'test-bin');
  mkdirSync(binaries,{recursive:true,mode:0o700});
  const python=path.join(binaries,'python3');
  writeFileSync(python,`#!/usr/bin/env bash
if [[ \$1 == -c && \$2 == *'pwd.getpwuid'* ]]; then printf '%s\\n' "\$USDOM_TEST_ACCOUNT_HOME"; exit 0; fi
exec /usr/bin/python3 "\$@"
`,{mode:0o700});
  chmodSync(python,0o700);
  return {...process.env,...extra,HOME:home,USDOM_TEST_ACCOUNT_HOME:home,
    PATH:`${binaries}:${nodeBin}:${process.env.PATH}`};
}
function interactiveBash(script,{cwd,env}) {
  const authorization=script.includes('source')
    ?'ASSINO COMMIT DE FONTE USDOM usdom-v1.2.3\n'
    :'ASSINO EVIDENCIA E TAG USDOM usdom-v1.2.3\n';
  return spawnSync('script',['-qefc',`bash ${script}`,'/dev/null'],{
    cwd,env,encoding:'utf8',input:authorization,
  });
}

test('source ceremony commits only source and rolls back a rejected index',()=>{
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-source-ceremony-'));
  try {
    const home=path.join(temporary,'home');
    const repository=path.join(temporary,'repo');
    const component=path.join(repository,'labs','usdom-reserve');
    for(const directory of ['scripts','sdk','config','docs','evidence']) {
      mkdirSync(path.join(component,directory),{recursive:true});
    }
    cpSync(path.join(projectRoot,'scripts','commit-release-source.sh'),
      path.join(component,'scripts','commit-release-source.sh'));
    cpSync(path.join(projectRoot,'scripts','pinned-shell-tool-functions.sh'),
      path.join(component,'scripts','pinned-shell-tool-functions.sh'));
    cpSync(path.join(projectRoot,'scripts','git-release-ceremony-boundary.sh'),
      path.join(component,'scripts','git-release-ceremony-boundary.sh'));
    cpSync(path.join(projectRoot,'scripts','check-release-tree-source-manifest.py'),
      path.join(component,'scripts','check-release-tree-source-manifest.py'));
    const scannerPath=path.join(component,'scripts','check-staged-sensitive-content.mjs');
    cpSync(path.join(projectRoot,'scripts','check-staged-sensitive-content.mjs'),scannerPath);
    writeFileSync(scannerPath,readFileSync(scannerPath,'utf8')+
      "\nif(process.env.USDOM_TEST_SWAP_INDEX==='1'&&path==='source.txt'){\n"+
      " const {spawnSync}=await import('node:child_process');\n"+
      " const written=spawnSync('/usr/bin/git',['-C',process.env.USDOM_TEST_REPOSITORY,'hash-object','-w','--stdin'],{input:'uninspected secret bytes\\n',encoding:'utf8'});\n"+
      " if(written.status!==0)process.exit(90);\n"+
      " const spec='100644,'+written.stdout.trim()+',source.txt';\n"+
      " const swapped=spawnSync('/usr/bin/git',['-C',process.env.USDOM_TEST_REPOSITORY,'update-index','--cacheinfo',spec]);\n"+
      " if(swapped.status!==0)process.exit(91);\n"+
      "}\n"+
      "if(process.env.USDOM_TEST_HIDE_TREE_ATTRIBUTES==='1'&&path==='source.txt'){\n"+
      " const {writeFileSync}=await import('node:fs');\n"+
      " writeFileSync(process.env.USDOM_TEST_ATTRIBUTES_PATH,'');\n"+
      "}\n"+
      "if(process.env.USDOM_TEST_REPLACE_SCANNER==='1'&&path==='yy-trigger.txt'){\n"+
      " const {writeFileSync}=await import('node:fs');\n"+
      " writeFileSync(process.env.USDOM_TEST_SCANNER_PATH,'process.stdin.resume();\\n');\n"+
      "}\n"+
      "if(process.env.USDOM_TEST_REPLACE_NPM==='1'&&path==='yy-npm-trigger.txt'){\n"+
      " const {writeFileSync}=await import('node:fs');\n"+
      " writeFileSync(process.env.USDOM_TEST_NPM_PATH,'#!/usr/bin/env node\\n// substituted after authorization\\nprocess.exit(0);\\n');\n"+
      "}\n");
    const fixtureScannerBytes=readFileSync(scannerPath);
    cpSync(path.join(projectRoot,'sdk','git-signature.mjs'),
      path.join(component,'sdk','git-signature.mjs'));
    writeFileSync(path.join(component,'package.json'),JSON.stringify({
      name:'ceremony-fixture',version:'1.2.3',private:true,type:'module',
      scripts:{test:'true','check:provenance':'true'},
    },null,2)+'\n');
    writeFileSync(path.join(component,'.gitignore'),'docs/CONTINUATION-STATE.md\n');
    writeFileSync(path.join(repository,'.gitignore'),'**/docs/CONTINUATION-STATE.md\n');
    writeFileSync(path.join(component,'docs','CONTINUATION-STATE.md'),'local only\n');
    writeFileSync(path.join(component,'config','mainnet-release-evidence.unconfigured.json'),
      JSON.stringify({releaseId:null,sourceCommit:null,sourceTag:null},null,2)+'\n');
    writeFileSync(path.join(component,'config','operator-intent.json'),JSON.stringify({
      release_signing_key_fingerprint:null,production_approved:false,deploy_authorized:false,
      real_funds_authorized:false,residual_risk_acceptance:{accepted:false,releaseId:null,
        sourceCommit:null},
    },null,2)+'\n');
    writeFileSync(path.join(component,'config','proof-reserve.unconfigured.json'),
      JSON.stringify({productionReady:true,realFundsAuthorized:true},null,2)+'\n');
    writeFileSync(path.join(component,'config','production-requirements.json'),JSON.stringify({
      mainnet_ready:true,deploy_authorized:true,real_funds_authorized:true,
      production_finality_selected:'ethereum-checkpoint',production_finality_approved:true,
    },null,2)+'\n');
    writeFileSync(path.join(repository,'source.txt'),'before\n');
    writeFileSync(path.join(repository,'preexisting.json'),
      '{"pass'+'word":"present-before-release-ceremony"}\n');
    const sourceFixturePackage=readFileSync(path.join(component,'package.json'));
    writeFileSync(path.join(component,'MANIFEST.sha256'),
      `${sha256(sourceFixturePackage)}  package.json\n`);
    command('git',['-C',repository,'init','-q']);
    command('git',['-C',repository,'config','user.name','Soren Planck']);
    command('git',['-C',repository,'config','user.email','sorenplanck@tutamail.com']);
    command('git',['-C',repository,'add','--all']);
    command('git',['-C',repository,'commit','-q','--no-gpg-sign','-m','fixture base']);
    const before=command('git',['-C',repository,'rev-parse','HEAD']);
    writeFileSync(path.join(repository,'source.txt'),'release source\n');
    writeFileSync(path.join(component,'evidence','kept-out.json'),'{}\n');

    const sshDirectory=path.join(home,'.ssh');
    mkdirSync(sshDirectory,{recursive:true,mode:0o700});
    const key=path.join(sshDirectory,'usdom-release-signing-ed25519');
    command('ssh-keygen',['-q','-t','ed25519','-N','','-f',key]);
    chmodSync(key,0o600); chmodSync(`${key}.pub`,0o600);
    const allowed=path.join(temporary,'allowed-signers');
    writeFileSync(allowed,
      `sorenplanck@tutamail.com ${readFileSync(`${key}.pub`,'utf8').trim()}\n`);
    command('git',['-C',repository,'config','gpg.format','ssh']);
    command('git',['-C',repository,'config','user.signingkey',key]);
    command('git',['-C',repository,'config','gpg.ssh.allowedSignersFile',allowed]);
    command('git',['-C',repository,'config','commit.gpgsign','true']);
    const hookMarker=path.join(temporary,'source-hook-ran');
    const preCommitHook=path.join(repository,'.git','hooks','pre-commit');
    writeFileSync(preCommitHook,`#!/usr/bin/env bash\nprintf ran > ${JSON.stringify(hookMarker)}\n`,
      {mode:0o700});

    const fsmonitorMarker=path.join(temporary,'fsmonitor-ran');
    const fsmonitor=path.join(temporary,'fsmonitor.sh');
    writeFileSync(fsmonitor,`#!/usr/bin/env bash\nprintf ran > ${JSON.stringify(fsmonitorMarker)}\nprintf 'clock-token\\n'\n`,{mode:0o700});
    command('git',['-C',repository,'config','core.fsmonitor',fsmonitor]);
    const fsmonitorRejected=interactiveBash('scripts/commit-release-source.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home),
    });
    assert.notEqual(fsmonitorRejected.status,0);
    assert.match(`${fsmonitorRejected.stderr}${fsmonitorRejected.stdout}`,
      /Executable or external Git configuration is forbidden/);
    assert.equal(existsSync(fsmonitorMarker),false,'fsmonitor must not execute in release ceremony');
    command('git',['-C',repository,'config','--unset','core.fsmonitor']);

    const inheritedSecret=interactiveBash('scripts/commit-release-source.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home),
    });
    assert.notEqual(inheritedSecret.status,0);
    assert.match(`${inheritedSecret.stderr}${inheritedSecret.stdout}`,
      /staged blob contains sensitive content/);
    assert.equal(command('git',['-C',repository,'rev-parse','HEAD']),before,
      'an unchanged secret inherited from the parent must not reach a signed source tree');
    writeFileSync(path.join(repository,'preexisting.json'),'{"password":"REDACTED"}\n');

    const executed=interactiveBash('scripts/commit-release-source.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home,{
        USDOM_TEST_SWAP_INDEX:'1',USDOM_TEST_REPOSITORY:repository,
      }),
    });
    assert.equal(executed.status,0,`${executed.stderr}\n${executed.stdout}`);
    assert.equal(existsSync(hookMarker),false,'repository pre-commit hook must not execute');
    const created=command('git',['-C',repository,'rev-parse','HEAD']);
    assert.notEqual(created,before);
    assert.equal(command('git',['-C',repository,'rev-parse','HEAD^']),before);
    assert.equal(command('git',['-C',repository,'show','-s','--format=%an <%ae>%n%cn <%ce>']),
      'Soren Planck <sorenplanck@tutamail.com>\nSoren Planck <sorenplanck@tutamail.com>');
    command('git',['-C',repository,'verify-commit','--raw','HEAD']);
    assert.equal(command('git',['-C',repository,'status','--porcelain=v1','--untracked-files=all']),
      '?? labs/usdom-reserve/evidence/kept-out.json');
    assert.equal(command('git',['-C',repository,'diff','--name-only','HEAD^','HEAD']),
      'preexisting.json\nsource.txt');
    assert.equal(command('git',['-C',repository,'show','HEAD:source.txt']),'release source');

    writeFileSync(path.join(repository,'yy-trigger.txt'),'benign trigger\n');
    writeFileSync(path.join(repository,'zz-release-secret.json'),
      '{"pass'+'word":"must-never-reach-a-signed-tree"}\n');
    const scannerSubstitution=interactiveBash('scripts/commit-release-source.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home,{
        USDOM_TEST_REPLACE_SCANNER:'1',USDOM_TEST_SCANNER_PATH:scannerPath,
      }),
    });
    assert.notEqual(scannerSubstitution.status,0);
    assert.match(`${scannerSubstitution.stderr}${scannerSubstitution.stdout}`,
      /staged blob contains sensitive content/);
    writeFileSync(scannerPath,fixtureScannerBytes);
    rmSync(path.join(repository,'yy-trigger.txt'));
    rmSync(path.join(repository,'zz-release-secret.json'));

    const fakeNpm=path.join(temporary,'test-bin','npm');
    writeFileSync(fakeNpm,'#!/usr/bin/env node\nprocess.exit(0);\n',{mode:0o700});
    writeFileSync(path.join(repository,'yy-npm-trigger.txt'),'replace npm after authorization\n');
    const npmSubstitution=interactiveBash('scripts/commit-release-source.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home,{
        USDOM_TEST_REPLACE_NPM:'1',USDOM_TEST_NPM_PATH:fakeNpm,
      }),
    });
    assert.notEqual(npmSubstitution.status,0,'a substituted post-signing npm must close the ceremony');
    assert.equal(command('git',['-C',repository,'rev-parse','HEAD']),created,
      'npm substitution must roll back the signed commit');
    rmSync(path.join(repository,'yy-npm-trigger.txt'));
    rmSync(fakeNpm);

    const fakeBasename=path.join(temporary,'test-bin','basename');
    writeFileSync(fakeBasename,'#!/usr/bin/env bash\nprintf \'safe-name.txt\\n\'\n',{mode:0o700});
    writeFileSync(path.join(repository,'benign-policy-fixture.key'),'public fixture bytes only\n');
    const basenameSubstitution=interactiveBash('scripts/commit-release-source.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home),
    });
    assert.notEqual(basenameSubstitution.status,0,
      'path policy must not trust a PATH-selected basename executable');
    assert.match(`${basenameSubstitution.stderr}${basenameSubstitution.stdout}`,
      /Sensitive-looking path entered the source index/);
    assert.equal(command('git',['-C',repository,'rev-parse','HEAD']),created);
    rmSync(path.join(repository,'benign-policy-fixture.key'));
    rmSync(fakeBasename);

    const fakeCat=path.join(temporary,'test-bin','cat');
    writeFileSync(fakeCat,"#!/usr/bin/env bash\nprintf '%s\\n' 'process.stdin.resume();'\n",{mode:0o700});
    writeFileSync(path.join(repository,'benign-invalid-utf8.txt'),Buffer.from([0xff]));
    const catSubstitution=interactiveBash('scripts/commit-release-source.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home),
    });
    assert.notEqual(catSubstitution.status,0,
      'scanner bytes must not come from a PATH-selected cat executable');
    assert.match(`${catSubstitution.stderr}${catSubstitution.stdout}`,
      /non-UTF8 staged blob lacks an approved public binary class/);
    assert.equal(command('git',['-C',repository,'rev-parse','HEAD']),created);
    rmSync(path.join(repository,'benign-invalid-utf8.txt'));
    rmSync(fakeCat);

    const redirectedIndex=interactiveBash('scripts/commit-release-source.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home,
        {GIT_INDEX_FILE:path.join(temporary,'foreign-index')}),
    });
    assert.notEqual(redirectedIndex.status,0);
    assert.match(`${redirectedIndex.stderr}${redirectedIndex.stdout}`,
      /Forbidden inherited Git environment variable: GIT_INDEX_FILE/);

    command('git',['-C',repository,'replace',created,before]);
    const replacedObject=interactiveBash('scripts/commit-release-source.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home),
    });
    assert.notEqual(replacedObject.status,0,'replace refs must close the ceremony');
    command('git',['-C',repository,'replace','-d',created]);

    const manifestPath=path.join(component,'MANIFEST.sha256');
    const originalManifest=readFileSync(manifestPath,'utf8');
    const requiredPath=path.join(component,'required-new.txt');
    const requiredBytes='required release source\n';
    writeFileSync(requiredPath,requiredBytes);
    writeFileSync(manifestPath,originalManifest+
      `${sha256(requiredBytes)}  required-new.txt\n`);
    const infoExclude=path.join(repository,'.git','info','exclude');
    const originalExclude=readFileSync(infoExclude,'utf8');
    writeFileSync(infoExclude,originalExclude+'\nlabs/usdom-reserve/required-new.txt\n');
    const omittedManifestSource=interactiveBash('scripts/commit-release-source.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home),
    });
    assert.notEqual(omittedManifestSource.status,0);
    assert.match(`${omittedManifestSource.stderr}${omittedManifestSource.stdout}`,
      /release tree lacks source-manifest blob/);
    writeFileSync(infoExclude,originalExclude);
    writeFileSync(manifestPath,originalManifest);
    rmSync(requiredPath);

    writeFileSync(path.join(repository,'.env'),'SECRET=not-a-real-secret\n');
    const rejected=interactiveBash('scripts/commit-release-source.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home),
    });
    assert.notEqual(rejected.status,0);
    assert.match(`${rejected.stderr}${rejected.stdout}`,/Sensitive-looking path entered the source index/);
    assert.equal(command('git',['-C',repository,'rev-parse','HEAD']),created);
    const staged=spawnSync('git',['-C',repository,'diff','--cached','--quiet','HEAD','--']);
    assert.equal(staged.status,0);

    rmSync(path.join(repository,'.env'));
    writeFileSync(path.join(repository,'.gitattributes'),'source.txt filter=evil\n');
    writeFileSync(path.join(repository,'source.txt'),'filtered release bytes\n');
    // The clean filter is byte-preserving so raw blob equality alone cannot
    // detect it. First info/attributes hides it from check-attr; after that
    // override is removed, the frozen tree itself must still be rejected.
    const localAttributes=path.join(repository,'.git','info','attributes');
    writeFileSync(localAttributes,'source.txt !filter\n');
    const locallyOverridden=interactiveBash('scripts/commit-release-source.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home),
    });
    assert.notEqual(locallyOverridden.status,0);
    assert.match(`${locallyOverridden.stderr}${locallyOverridden.stdout}`,
      /Repository-local Git attributes are forbidden/);
    rmSync(localAttributes);
    const filtered=interactiveBash('scripts/commit-release-source.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home,{
        USDOM_TEST_HIDE_TREE_ATTRIBUTES:'1',
        USDOM_TEST_ATTRIBUTES_PATH:path.join(repository,'.gitattributes'),
      }),
    });
    assert.notEqual(filtered.status,0);
    assert.match(`${filtered.stderr}${filtered.stdout}`,
      /Transforming attribute is forbidden in inspected release tree/);
    assert.equal(command('git',['-C',repository,'rev-parse','HEAD']),created);
    assert.equal(spawnSync('git',['-C',repository,'diff','--cached','--quiet','HEAD','--']).status,0);
  } finally { rmSync(temporary,{recursive:true,force:true}); }
});

test('evidence ceremony rolls back a failed gate then signs the exact child and tag',()=>{
  const temporary=mkdtempSync(path.join(os.tmpdir(),'usdom-evidence-ceremony-'));
  try {
    const home=path.join(temporary,'home');
    const repository=path.join(temporary,'repo');
    const component=path.join(repository,'labs','usdom-reserve');
    for(const directory of ['scripts','sdk','config','docs','evidence']) {
      mkdirSync(path.join(component,directory),{recursive:true});
    }
    cpSync(path.join(projectRoot,'scripts','commit-release-evidence.sh'),
      path.join(component,'scripts','commit-release-evidence.sh'));
    cpSync(path.join(projectRoot,'scripts','pinned-shell-tool-functions.sh'),
      path.join(component,'scripts','pinned-shell-tool-functions.sh'));
    cpSync(path.join(projectRoot,'scripts','git-release-ceremony-boundary.sh'),
      path.join(component,'scripts','git-release-ceremony-boundary.sh'));
    cpSync(path.join(projectRoot,'scripts','check-release-tree-source-manifest.py'),
      path.join(component,'scripts','check-release-tree-source-manifest.py'));
    cpSync(path.join(projectRoot,'scripts','check-staged-sensitive-content.mjs'),
      path.join(component,'scripts','check-staged-sensitive-content.mjs'));
    cpSync(path.join(projectRoot,'sdk','git-signature.mjs'),
      path.join(component,'sdk','git-signature.mjs'));
    writeFileSync(path.join(component,'scripts','check-mainnet-readiness.mjs'),
      `const failed=process.env.USDOM_TEST_FAIL_GATE==='1';\n`+
      `process.stdout.write(JSON.stringify({ready:!failed,blockers:failed?[{code:'fixture'}]:[]})+'\\n');\n`+
      `if(failed) process.exitCode=1;\n`);
    writeFileSync(path.join(component,'package.json'),JSON.stringify({
      name:'evidence-ceremony-fixture',version:'1.2.3',private:true,type:'module',
      scripts:{'check:provenance':'true'},
    },null,2)+'\n');
    const packageBytes=readFileSync(path.join(component,'package.json'));
    writeFileSync(path.join(component,'MANIFEST.sha256'),
      `${sha256(packageBytes)}  package.json\n`);
    writeFileSync(path.join(component,'.gitignore'),'docs/CONTINUATION-STATE.md\n');
    writeFileSync(path.join(repository,'.gitignore'),'**/docs/CONTINUATION-STATE.md\n');
    writeFileSync(path.join(component,'docs','CONTINUATION-STATE.md'),'local only\n');
    writeFileSync(path.join(component,'config','mainnet-release-evidence.unconfigured.json'),
      JSON.stringify({releaseId:null,sourceCommit:null,sourceTag:null},null,2)+'\n');
    writeFileSync(path.join(component,'config','operator-intent.json'),JSON.stringify({
      release_signing_key_fingerprint:null,production_approved:false,deploy_authorized:false,
      real_funds_authorized:false,undefined:['pending'],residual_risk_acceptance:{accepted:false,
        releaseId:null,sourceCommit:null},
    },null,2)+'\n');

    command('git',['-C',repository,'init','-q']);
    command('git',['-C',repository,'config','user.name','Soren Planck']);
    command('git',['-C',repository,'config','user.email','sorenplanck@tutamail.com']);
    const sshDirectory=path.join(home,'.ssh');
    mkdirSync(sshDirectory,{recursive:true,mode:0o700});
    const key=path.join(sshDirectory,'usdom-release-signing-ed25519');
    command('ssh-keygen',['-q','-t','ed25519','-N','','-f',key]);
    chmodSync(key,0o600); chmodSync(`${key}.pub`,0o600);
    const allowed=path.join(temporary,'allowed-signers');
    writeFileSync(allowed,
      `sorenplanck@tutamail.com ${readFileSync(`${key}.pub`,'utf8').trim()}\n`);
    command('git',['-C',repository,'config','gpg.format','ssh']);
    command('git',['-C',repository,'config','user.signingkey',key]);
    command('git',['-C',repository,'config','gpg.ssh.allowedSignersFile',allowed]);
    command('git',['-C',repository,'config','commit.gpgsign','true']);
    command('git',['-C',repository,'config','tag.gpgsign','true']);
    command('git',['-C',repository,'add','--all']);
    command('git',['-C',repository,'commit','-q','-S','-m','USDOM immutable source fixture']);
    const sourceCommit=command('git',['-C',repository,'rev-parse','HEAD']);
    const fingerprint=command('ssh-keygen',['-lf',`${key}.pub`,'-E','sha256']).split(/\s+/)[1];
    const sourceTag='usdom-v1.2.3';
    writeFileSync(path.join(component,'config','mainnet-release-evidence.unconfigured.json'),
      JSON.stringify({releaseId:sourceTag,sourceCommit,sourceTag},null,2)+'\n');
    writeFileSync(path.join(component,'config','operator-intent.json'),JSON.stringify({
      release_signing_key_fingerprint:fingerprint,production_approved:true,deploy_authorized:true,
      real_funds_authorized:true,undefined:[],residual_risk_acceptance:{accepted:true,
        releaseId:sourceTag,sourceCommit},
    },null,2)+'\n');
    writeFileSync(path.join(component,'evidence','report.json'),'{}\n');

    const failed=interactiveBash('scripts/commit-release-evidence.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home,
        {USDOM_TEST_FAIL_GATE:'1'}),
    });
    assert.notEqual(failed.status,0);
    assert.equal(command('git',['-C',repository,'rev-parse','HEAD']),sourceCommit);
    assert.notEqual(spawnSync('git',['-C',repository,'rev-parse','--verify',
      `refs/tags/${sourceTag}`]).status,0);
    assert.equal(spawnSync('git',['-C',repository,'diff','--cached','--quiet','HEAD','--']).status,0);

    const executed=interactiveBash('scripts/commit-release-evidence.sh',{
      cwd:component,env:accountHomeEnvironment(temporary,home),
    });
    assert.equal(executed.status,0,`${executed.stderr}\n${executed.stdout}`);
    const evidenceCommit=command('git',['-C',repository,'rev-parse','HEAD']);
    assert.equal(command('git',['-C',repository,'rev-parse','HEAD^']),sourceCommit);
    assert.equal(command('git',['-C',repository,'rev-parse',`refs/tags/${sourceTag}^{commit}`]),
      evidenceCommit);
    command('git',['-C',repository,'verify-commit','--raw',evidenceCommit]);
    command('git',['-C',repository,'verify-tag','--raw',sourceTag]);
    assert.equal(command('git',['-C',repository,'status','--porcelain=v1','--untracked-files=all']),'');
    assert.deepEqual(command('git',['-C',repository,'diff','--name-only',sourceCommit,evidenceCommit])
      .split('\n').sort(),[
      'labs/usdom-reserve/config/mainnet-release-evidence.unconfigured.json',
      'labs/usdom-reserve/config/operator-intent.json',
      'labs/usdom-reserve/evidence/report.json',
    ]);
  } finally { rmSync(temporary,{recursive:true,force:true}); }
});
