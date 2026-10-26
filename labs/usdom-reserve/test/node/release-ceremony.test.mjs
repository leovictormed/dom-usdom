import test from 'node:test';
import assert from 'node:assert/strict';
import {
  chmodSync,cpSync,mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync,
} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import os from 'node:os';
import path from 'node:path';

const projectRoot=fileURLToPath(new URL('../..',import.meta.url));

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
    PATH:`${binaries}:${process.env.PATH}`};
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
    cpSync(path.join(projectRoot,'sdk','git-signature.mjs'),
      path.join(component,'sdk','git-signature.mjs'));
    writeFileSync(path.join(component,'package.json'),JSON.stringify({
      name:'ceremony-fixture',version:'1.2.3',private:true,type:'module',
      scripts:{test:'true','check:provenance':'true'},
    },null,2)+'\n');
    writeFileSync(path.join(component,'.gitignore'),'docs/CONTINUATION-STATE.md\n');
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

    const executed=spawnSync('bash',['scripts/commit-release-source.sh'],{
      cwd:component,encoding:'utf8',env:accountHomeEnvironment(temporary,home),
    });
    assert.equal(executed.status,0,`${executed.stderr}\n${executed.stdout}`);
    const created=command('git',['-C',repository,'rev-parse','HEAD']);
    assert.notEqual(created,before);
    assert.equal(command('git',['-C',repository,'rev-parse','HEAD^']),before);
    assert.equal(command('git',['-C',repository,'show','-s','--format=%an <%ae>%n%cn <%ce>']),
      'Soren Planck <sorenplanck@tutamail.com>\nSoren Planck <sorenplanck@tutamail.com>');
    command('git',['-C',repository,'verify-commit','--raw','HEAD']);
    assert.equal(command('git',['-C',repository,'status','--porcelain=v1','--untracked-files=all']),
      '?? labs/usdom-reserve/evidence/kept-out.json');
    assert.equal(command('git',['-C',repository,'diff','--name-only','HEAD^','HEAD']),'source.txt');

    writeFileSync(path.join(repository,'.env'),'SECRET=not-a-real-secret\n');
    const rejected=spawnSync('bash',['scripts/commit-release-source.sh'],{
      cwd:component,encoding:'utf8',env:accountHomeEnvironment(temporary,home),
    });
    assert.notEqual(rejected.status,0);
    assert.match(rejected.stderr,/Sensitive-looking path entered the source index/);
    assert.equal(command('git',['-C',repository,'rev-parse','HEAD']),created);
    const staged=spawnSync('git',['-C',repository,'diff','--cached','--quiet','HEAD','--']);
    assert.equal(staged.status,0);
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
    writeFileSync(path.join(component,'.gitignore'),'docs/CONTINUATION-STATE.md\n');
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

    const failed=spawnSync('bash',['scripts/commit-release-evidence.sh'],{
      cwd:component,encoding:'utf8',env:accountHomeEnvironment(temporary,home,
        {USDOM_TEST_FAIL_GATE:'1'}),
    });
    assert.notEqual(failed.status,0);
    assert.equal(command('git',['-C',repository,'rev-parse','HEAD']),sourceCommit);
    assert.notEqual(spawnSync('git',['-C',repository,'rev-parse','--verify',
      `refs/tags/${sourceTag}`]).status,0);
    assert.equal(spawnSync('git',['-C',repository,'diff','--cached','--quiet','HEAD','--']).status,0);

    const executed=spawnSync('bash',['scripts/commit-release-evidence.sh'],{
      cwd:component,encoding:'utf8',env:accountHomeEnvironment(temporary,home),
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
