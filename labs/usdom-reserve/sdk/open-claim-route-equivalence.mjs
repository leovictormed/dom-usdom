import {openClaimSemanticContract,assertSemanticContractSource} from './open-claim-route-semantics.mjs';

function activeShell(source) {
  return source.split('\n').filter(line=>!/^\s*#/.test(line)).join('\n')
    .replace(/[ \t]*\\\n\s*/g,' ');
}

function escaped(value) { return value.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'); }

function containsInvocation(source,fragment) {
  const normalized=activeShell(source);
  return new RegExp(`(?:^|[\\s;|&/])${escaped(fragment)}(?=$|[\\s;|&])`,'m').test(normalized);
}

function auditedCommandTarget(command,packageScripts) {
  const npm=/^(?:[A-Z][A-Z0-9_]*=[A-Za-z0-9._-]+ )*npm run --silent ([a-z0-9][a-z0-9:_-]*)(?:\s|$)/.exec(command);
  if(npm) {
    const packageCommand=packageScripts[npm[1]];
    const dispatched=typeof packageCommand==='string'
      ?packageCommand.replace(/^\.\/scripts\/mainnet-tool-dispatcher\s+/,''):undefined;
    const target=dispatched
      ?dispatched.match(/^(?:bash|node|python3)\s+(scripts\/[A-Za-z0-9._/-]+)(?:\s+[A-Za-z0-9._/-]+)*$/)?.[1]
      :undefined;
    if(!target) throw new Error(`semantic route package command is not one direct audited script: ${command}`);
    return target;
  }
  const direct=/^(?:node|bash|python3)\s+(scripts\/[A-Za-z0-9._/-]+)(?:\s|$)/.exec(command);
  return direct?.[1]??null;
}

const staleReserveBindings=Object.freeze([
  'pendingBurnPage','burnIntentHash','initialPauseRequired',
  '27be31d80767bba9ed0369e89e4c0a408a694b16f82d7747f95b8d4179776a3d',
  '2044939ee66c2afafa3e165e700a2884687b0723b956b46b503b74752130f921',
  '86808fa0de635cbc3bc34710a633fae6a16c36e9bf947b68c616399ad9ddfd98',
]);

export function assertNoStaleReserveBindings(sources) {
  if(!Array.isArray(sources)||sources.some(source=>typeof source!=='string')) {
    throw new Error('generated route sources are invalid');
  }
  const corpus=sources.join('\n');
  for(const stale of staleReserveBindings) {
    if(corpus.includes(stale)) throw new Error(`stale reserve ABI/runtime binding in generated routes: ${stale}`);
  }
  return true;
}

export function assertOpenClaimRouteEquivalence({plan,phaseSources,packageScripts,readSource}) {
  if(!plan||!Array.isArray(plan.entries)||plan.entries.length<1
      ||!(phaseSources instanceof Map)||!packageScripts||typeof packageScripts!=='object'
      ||typeof readSource!=='function') {
    throw new Error('open-claim route equivalence inputs are invalid');
  }
  const semanticIds=new Map();
  for(const row of plan.entries) {
    const expected=openClaimSemanticContract(row.claim);
    if(JSON.stringify(row.semanticEvidence)!==JSON.stringify(expected)) {
      throw new Error(`semantic evidence contract drift for ${row.claim}`);
    }
    const phaseSource=phaseSources.get(row.phase);
    if(typeof phaseSource!=='string'||phaseSource.length===0) {
      throw new Error(`semantic phase body missing for ${row.claim}`);
    }
    for(const command of [...row.evidenceProducerCommands,...row.independentValidatorCommands]) {
      if(!containsInvocation(phaseSource,command)) {
        throw new Error(`semantic route command is not an active invocation for ${row.claim}: ${command}`);
      }
      const target=auditedCommandTarget(command,packageScripts);
      if(target) readSource(target);
    }
    const implementation=readSource(expected.file);
    assertSemanticContractSource(expected,implementation);
    const prior=semanticIds.get(expected.id);
    if(prior&&prior.file!==expected.file) {
      throw new Error(`semantic evidence ID is ambiguous: ${expected.id}`);
    }
    semanticIds.set(expected.id,expected);
  }
  return Object.freeze({claimCount:plan.entries.length,semanticContractCount:semanticIds.size});
}
