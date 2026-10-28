import {existsSync,readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {assertNoStaleReserveBindings,assertOpenClaimRouteEquivalence}
  from '../sdk/open-claim-route-equivalence.mjs';
import {validateClosedMainnetExecutionPlan} from '../sdk/closed-mainnet-phase-dependency.mjs';
import {auditReserveArtifact} from '../sdk/reserve-artifact-safety.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const generated=spawnSync(process.execPath,[path.join(root,'scripts/write-open-claims-execution-plan.mjs')],{encoding:'utf8'});
if(generated.status!==0) throw new Error('plan writer failed');
const plan=JSON.parse(generated.stdout);
validateClosedMainnetExecutionPlan(plan);
if(plan.schema!=='usdom-open-claims-execution-plan/v1'||plan.claimCount!==plan.entries.length
  ||new Set(plan.entries.map(row=>row.claim)).size!==plan.claimCount) throw new Error('open-claims plan does not cover each current claim exactly once');
if(!Array.isArray(plan.phaseOrder)||new Set(plan.phaseOrder).size!==plan.phaseOrder.length) throw new Error('phase dependency order is invalid');
if(!Array.isArray(plan.phaseArtifacts)||plan.phaseArtifacts.length!==plan.phaseOrder.length) throw new Error('phase artifact catalog is incomplete');
const packageJson=JSON.parse(readFileSync(path.join(root,'package.json'),'utf8'));
const reserveArtifact=JSON.parse(readFileSync(
  path.join(root,'out/USDOMProofReserve.sol/USDOMProofReserve.json'),'utf8'));
auditReserveArtifact(reserveArtifact,{root});
const ubuntuBootstrap=readFileSync(path.join(root,'scripts/bootstrap-ubuntu-24.04-dependencies.sh'),'utf8');
const pilotEntry=readFileSync(path.join(root,'scripts/prepare-closed-mainnet-pilot.sh'),'utf8');
if(!ubuntuBootstrap.includes('apt-get install --no-install-recommends --yes "${specs[@]}"')
  ||ubuntuBootstrap.includes('sudo ')||ubuntuBootstrap.includes('curl ')
  ||!ubuntuBootstrap.includes("[[ $mode == --verify-only || $mode == --install ]]")
  ||!ubuntuBootstrap.includes("sha256sum \"$executable\"")) throw new Error('Ubuntu bootstrap is not authenticated and explicit');
if(!pilotEntry.includes('--verify-only')||!pilotEntry.includes('--generate-plan')
  ||!pilotEntry.includes('node scripts/check-open-claims-execution-plan.mjs')
  ||/(?:YOUR_|CHANGE_ME|PLACEHOLDER|REPLACE_ME|<[A-Za-z][A-Za-z0-9 _.-]*>)/.test(pilotEntry)) throw new Error('pilot entrypoint is incomplete');
const irreversibleTargets=new Map([
  ['execute-safe-controls-deployment-secret','scripts/execute-safe-control-deployment.sh'],
  ['execute-mainnet-deployment-secret','scripts/execute-mainnet-deployment.sh'],
  ['execute-reserve-resume-secret','scripts/execute-reserve-resume.sh'],
  ['execute-safe-recovery-secret','scripts/execute-recoverable-safe-recovery.sh'],
  ['execute-pilot-deposit-secret','scripts/execute-closed-mainnet-deposit.sh'],
  ['execute-pilot-redemption-secret','scripts/execute-closed-mainnet-redemption.sh'],
]);
function assertAllowedPrompts(source,label) {
  for(const line of source.split('\n').filter(value=>/^\s*(?:IFS=\s*)?read\s.*(?:-p|--prompt)/.test(value))) {
    const secret=/^\s*(?:IFS=\s*)?read\s.*(?:-s\b|--silent\b)/.test(line);
    const irreversible=/Digite (?:AUTORIZO|ASSINO|CONFIRMO)/.test(line);
    if(!secret&&!irreversible) throw new Error(`manual public-data or navigation prompt in ${label}: ${line.trim()}`);
  }
  if(/(?:nano|vim|vi)\s+config\//.test(source)) throw new Error(`manual configuration edit in ${label}`);
}
for(const [phaseIndex,phase] of plan.phaseOrder.entries()) {
  const result=spawnSync('bash',['scripts/generate-closed-mainnet-phase-command.sh',phase],{cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'}});
  if(result.status!==0) throw new Error(`unknown or invalid phase: ${phase}`);
  const syntax=spawnSync('bash',['-n'],{encoding:'utf8',input:result.stdout,env:{PATH:'/usr/bin:/bin'}});
  if(syntax.status!==0) throw new Error(`invalid generated Bash for ${phase}`);
  const artifact=plan.phaseArtifacts[phaseIndex];
  const phaseSha256=createHash('sha256').update(result.stdout).digest('hex');
  if(artifact?.phase!==phase||artifact.ordinal!==phaseIndex+1
    ||JSON.stringify(artifact.prerequisitePhases)!==JSON.stringify(plan.phaseOrder.slice(0,phaseIndex))
    ||artifact.generatedScriptSha256!==phaseSha256
    ||artifact.generatedScriptBytes!==Buffer.byteLength(result.stdout)) {
    throw new Error(`phase artifact commitment or dependency chain is invalid: ${phase}`);
  }
  const begin=result.stdout.indexOf('check-closed-mainnet-phase-dependency.mjs begin');
  const body=result.stdout.indexOf('phase_body() {');
  const execute=result.stdout.lastIndexOf('\nphase_body\n');
  const complete=result.stdout.lastIndexOf('check-closed-mainnet-phase-dependency.mjs complete');
  if(begin<0||body<=begin||execute<=body||complete<=execute) {
    throw new Error(`phase dependency enforcement is incomplete: ${phase}`);
  }
  for(const required of ['export LC_ALL=C LANG=C TZ=UTC','umask 077','unset BASH_ENV ENV CDPATH NODE_OPTIONS NODE_PATH',
    'hash -r','test "$(command -v node)" = /usr/lib/chatgpt/resources/cua_node/bin/node',
    'test "$(command -v forge)" = /home/leonardov/.foundry/bin/forge',
    'test ! -L "$USDOM_CONTROL_EVIDENCE_DIRECTORY"',
    'stat -c \'%u:%a\' "$USDOM_CONTROL_EVIDENCE_DIRECTORY"',
    'test ! -L "$USDOM_MAINNET_PREFLIGHT_RPC_SOURCES_FILE"']) {
    if(!result.stdout.includes(required)) throw new Error(`controlled environment missing in ${phase}: ${required}`);
  }
  assertAllowedPrompts(result.stdout,`generated phase ${phase}`);
  if(/trap ['"]rm -rf/.test(result.stdout)) throw new Error(`unauthenticated recursive cleanup in ${phase}`);
  if(result.stdout.includes('rm -rf --')&&(!result.stdout.includes("stat -c '%u:%d:%i:%a'")
    ||!result.stdout.includes('_identity'))) throw new Error(`recursive cleanup lacks inode authentication in ${phase}`);
  if(/<[A-Za-z][A-Za-z0-9 _.-]*>|YOUR_|CHANGE_ME|PLACEHOLDER|REPLACE_ME|\bTODO\b|\bTBD\b/.test(result.stdout)) throw new Error(`placeholder in generated phase: ${phase}`);
  for(const match of result.stdout.matchAll(/npm run --silent ([a-z0-9:_-]+)/g)) {
    const command=packageJson.scripts[match[1]];
    if(typeof command!=='string'||command.length===0) throw new Error(`missing npm script ${match[1]} in ${phase}`);
    const target=command.match(/^(?:bash|node|python3)\s+([^ ]+)/)?.[1];
    if(target&&!existsSync(path.join(root,target))) throw new Error(`missing target ${target} for npm script ${match[1]}`);
    if(target&&target.endsWith('.sh')) assertAllowedPrompts(readFileSync(path.join(root,target),'utf8'),target);
  }
  for(const match of result.stdout.matchAll(/forge test --match-path ([^ ]+)/g)) if(!existsSync(path.join(root,match[1]))) throw new Error(`missing Forge test path ${match[1]}`);
  const irreversibleTarget=irreversibleTargets.get(phase);
  if(irreversibleTarget) {
    const source=readFileSync(path.join(root,irreversibleTarget),'utf8');
    if(phase==='execute-safe-controls-deployment-secret') {
      if(!source.includes('prepare-safe-control-deployment-relayer-envelope.mjs')
        ||!source.includes('exit 78')||!source.includes('Digite AUTORIZO TRANSMITIR SAFE $role NONCE $nonce TX $tx_hash')
        ||!source.includes('eth_getTransactionByHash')) throw new Error(`irreversible phase lacks exact relayer envelope and transaction-hash authorization: ${phase}`);
      continue;
    }
    if(phase==='execute-pilot-deposit-secret') {
      if(!source.includes('usdom-onekey-eip712-signing/v1')
        ||!source.includes('materialize-safe-deposit-relayer.mjs envelope')
        ||!source.includes('safe-deposit-$kind-safe-envelope.json')
        ||!source.includes('RELAYER_SIGNATURE_REQUIRED')||!source.includes('exit 78')
        ||!source.includes('BROADCAST_REVALIDATION_REQUIRED')||!source.includes('exit 80')) {
        throw new Error(`irreversible phase lacks Safe authorization and exact gas-relayer boundary: ${phase}`);
      }
      continue;
    }
    const review=source.indexOf('AUTHORIZE REVIEW');
    const authorization=source.indexOf('Digite AUTORIZO');
    if(review<0||authorization<0||review>authorization||!source.includes('chainId=1')
      ||!source.includes('gasLimit=')||!source.includes('maxFeePerGas=')
      ||!source.includes('maximumGasCostWei=')) throw new Error(`irreversible phase lacks review before authorization: ${phase}`);
  }
}
const materializerSource=readFileSync(path.join(root,'scripts/materialize-closed-mainnet-phase-script.sh'),'utf8');
if(!materializerSource.includes('check-closed-mainnet-phase-dependency.mjs \\\n  materialize "$phase" "$candidate"')) {
  throw new Error('phase materializer does not authenticate the current execution plan');
}
const phases=new Set(plan.phaseOrder);
const generatedPhaseSources=new Map(plan.phaseOrder.map(phase=>[phase,spawnSync('bash',
  ['scripts/generate-closed-mainnet-phase-command.sh',phase],{cwd:root,encoding:'utf8',env:{PATH:'/usr/bin:/bin'}}).stdout]));
assertNoStaleReserveBindings([generated.stdout,...generatedPhaseSources.values()]);
const cleanBash='env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH /usr/bin/bash --noprofile --norc';
const materializer=`${cleanBash} scripts/materialize-closed-mainnet-phase-script.sh`;
const phaseDirectory='/home/leonardov/usdom-mainnet-private/operator-phases';
const activePhaseSource=source=>source.split('\n').filter(line=>!/^\s*#/.test(line))
  .join('\n').replace(/[ \t]*\\\n\s*/g,' ');
for(const row of plan.entries) {
  const phaseIndex=plan.phaseOrder.indexOf(row.phase),artifact=plan.phaseArtifacts[phaseIndex];
  if(!phases.has(row.phase)||!row.completionEvidence||row.closingClaim!==`operational-claims-ledger.json#/${row.claim}`
    ||row.phaseOrdinal!==artifact?.ordinal||row.phaseScriptSha256!==artifact?.generatedScriptSha256
    ||row.phaseScriptBytes!==artifact?.generatedScriptBytes) throw new Error(`unsatisfied execution route for ${row.claim}`);
  if(row.generateCommand!==`${materializer} ${row.phase}`||row.validateCommand!==`${cleanBash} -n ${phaseDirectory}/${row.phase}.sh`||row.executeCommand!==`${cleanBash} ${phaseDirectory}/${row.phase}.sh`) throw new Error(`invalid commands for ${row.claim}`);
  if(/(?:cast send|eth_sendRawTransaction|wallet sign|git push|mine|anvil)/.test(row.generateCommand+row.validateCommand)) throw new Error(`generation or validation can mutate external state for ${row.claim}`);
  if(!row.generateCommand.startsWith('env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH ')
    ||!row.validateCommand.startsWith('env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH ')
    ||!row.executeCommand.startsWith('env -u BASH_ENV -u ENV -u NODE_OPTIONS -u NODE_PATH ')) throw new Error(`ambient shell injection possible for ${row.claim}`);
  const normalizedPhase=activePhaseSource(generatedPhaseSources.get(row.phase));
  if(!Array.isArray(row.evidenceProducerCommands)
      ||row.evidenceProducerCommands.some(command=>typeof command!=='string'||command.length===0
        ||!normalizedPhase.includes(command))) {
    throw new Error(`claim evidence producer is absent from its phase: ${row.claim}`);
  }
  if(!['external-operation','awaiting-external-ceremony','awaiting-verified-installation'].includes(row.implementationStatus)) {
    throw new Error(`claim implementation status is not classified: ${row.claim}`);
  }
  const missing=row.implementationStatus!=='external-operation';
  if((row.evidenceProducerCommands.length===0)!==missing
    ||(row.independentValidatorCommands.length===0)!==missing) {
    throw new Error(`claim producer/validator completeness disagrees with implementation status: ${row.claim}`);
  }
  if(!Array.isArray(row.independentValidatorCommands)
    ||row.independentValidatorCommands.some(command=>typeof command!=='string'||command.length===0
      ||!normalizedPhase.includes(command))) {
    throw new Error(`claim independent validator is absent from its phase: ${row.claim}`);
  }
  if(!missing) {
    const phaseSource=normalizedPhase;
    const producerEnd=Math.max(...row.evidenceProducerCommands.map(command=>phaseSource.indexOf(command)));
    const validatorStart=Math.min(...row.independentValidatorCommands.map(command=>phaseSource.indexOf(command)));
    if(producerEnd<0||validatorStart<0||validatorStart<=producerEnd) {
      throw new Error(`claim validator does not follow its producer: ${row.claim}`);
    }
  }
  if(row.readinessConsumer!=='readinessRequirementKeys(real-funds)') {
    throw new Error(`claim is not explicitly consumed by readiness: ${row.claim}`);
  }
}
const equivalence=assertOpenClaimRouteEquivalence({plan,phaseSources:generatedPhaseSources,
  packageScripts:packageJson.scripts,readSource:relative=>readFileSync(path.join(root,relative),'utf8')});
if(equivalence.claimCount!==plan.claimCount) throw new Error('open-claim semantic route coverage is incomplete');
console.log(`PASS: open-claims execution plan integrity ${plan.claimCount}/${plan.claimCount}`);
