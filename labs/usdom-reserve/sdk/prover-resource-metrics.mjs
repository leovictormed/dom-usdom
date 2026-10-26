const maximumWallMilliseconds=30n*24n*60n*60n*1000n;
const maximumResidentKiB=64n*1024n*1024n;

function elapsedMilliseconds(value) {
  const parts=value.trim().split(':');
  if(parts.length<2 || parts.length>3
      || parts.some(part=>!/^[0-9]+(?:\.[0-9]+)?$/.test(part))) {
    throw new Error('prover elapsed wall time is not canonical');
  }
  const seconds=parts.map(Number).reduce((total,part)=>total*60+part,0);
  if(!Number.isFinite(seconds) || seconds<=0) {
    throw new Error('prover elapsed wall time is invalid');
  }
  const milliseconds=BigInt(Math.round(seconds*1000));
  if(milliseconds===0n || milliseconds>maximumWallMilliseconds) {
    throw new Error('prover elapsed wall time exceeds its bound');
  }
  return milliseconds;
}

/** Parse the bounded fields emitted by GNU `/usr/bin/time -v`. */
export function parseProverResourceMetrics(contents) {
  if(typeof contents!=='string' || Buffer.byteLength(contents)>64*1024) {
    throw new Error('prover resource log must be bounded UTF-8 text');
  }
  const elapsed=contents.match(/^\s*Elapsed \(wall clock\) time \([^)]*\):\s*(.+)$/m)?.[1];
  const resident=contents.match(/^\s*Maximum resident set size \(kbytes\):\s*([0-9]+)$/m)?.[1];
  const status=contents.match(/^\s*Exit status:\s*([0-9]+)$/m)?.[1];
  if(!elapsed || !resident || !/^[1-9][0-9]*$/.test(resident) || status!=='0') {
    throw new Error('prover resource log is incomplete or records a failed command');
  }
  const peakResidentKiB=BigInt(resident);
  if(peakResidentKiB>maximumResidentKiB) {
    throw new Error('prover peak resident memory exceeds its bound');
  }
  return Object.freeze({provingWallMilliseconds:elapsedMilliseconds(elapsed).toString(),
    peakResidentKiB:peakResidentKiB.toString()});
}
