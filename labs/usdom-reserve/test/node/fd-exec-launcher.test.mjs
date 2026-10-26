import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,chmodSync,linkSync,symlinkSync,rmSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync,spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const root=new URL('../..',import.meta.url).pathname,source=join(root,'tools/usdom-fd-exec.c');
test('fd launcher rejects substitutions and executes the authenticated descriptor',()=>{
 const directory=mkdtempSync(join(tmpdir(),'usdom-fdexec-')),launcher=join(directory,'fdexec'),childSource=join(directory,'child.c'),child=join(directory,'child');
 try {execFileSync('cc',['-O2','-Wall','-Wextra','-Werror',source,'-lcrypto','-o',launcher]);writeFileSync(childSource,'#include <stdio.h>\n#include <stdlib.h>\n#include <sys/prctl.h>\nint main(int argc,char **argv){printf("good|%s|%s|%d|%d|%s\\n",getenv("PATH"),getenv("HOME"),(int)prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0),argc,argc>1?argv[1]:"");return 0;}\n');execFileSync('cc',['-O2','-Wall','-Wextra','-Werror',childSource,'-o',child]);chmodSync(child,0o700);const sha=createHash('sha256').update(readFileSync(child)).digest('hex');const hostileEnv={...process.env,HOME:'/tmp',PATH:'/attacker/bin'};let result=spawnSync(launcher,[directory,'child',sha,'--','hello'],{encoding:'utf8',env:hostileEnv});assert.equal(result.status,0,result.stderr);assert.equal(result.stdout,'good|/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|/tmp|1|2|hello\n');result=spawnSync(launcher,[directory,'child','0'.repeat(64),'--']);assert.equal(result.status,126);result=spawnSync(launcher,[directory,'child',sha,'--'],{env:{PATH:'/usr/bin:/bin',HOME:'relative'}});assert.equal(result.status,126);chmodSync(child,0o4700);result=spawnSync(launcher,[directory,'child',sha,'--']);assert.equal(result.status,126);chmodSync(child,0o700);symlinkSync('child',join(directory,'link'));result=spawnSync(launcher,[directory,'link',sha,'--']);assert.equal(result.status,126);linkSync(child,join(directory,'hard'));result=spawnSync(launcher,[directory,'child',sha,'--']);assert.equal(result.status,126);}finally{rmSync(directory,{recursive:true,force:true});}
});
