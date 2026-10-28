const maximumWallMilliseconds=30n*24n*60n*60n*1000n;
const maximumResidentKiB=64n*1024n*1024n;

function elapsedMilliseconds(value) {
  const text=value.trim();
  const three=text.match(/^([0-9]{1,3}):([0-5][0-9]):([0-5][0-9])(?:\.([0-9]{1,3}))?$/);
  const two=text.match(/^([0-9]{1,5}):([0-5][0-9])(?:\.([0-9]{1,3}))?$/);
  if(!three&&!two) {
    throw new Error('prover elapsed wall time is not canonical');
  }
  const hours=three?BigInt(three[1]):0n;
  const minutes=BigInt(three?three[2]:two[1]);
  const seconds=BigInt(three?three[3]:two[2]);
  const fraction=three?.[4]??two?.[3]??'';
  const milliseconds=(hours*3600n+minutes*60n+seconds)*1000n
    +BigInt(fraction.padEnd(3,'0')||'0');
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
  if(!elapsed || !resident || resident.length>8 || !/^[1-9][0-9]*$/.test(resident)
      || status!=='0') {
    throw new Error('prover resource log is incomplete or records a failed command');
  }
  const peakResidentKiB=BigInt(resident);
  if(peakResidentKiB>maximumResidentKiB) {
    throw new Error('prover peak resident memory exceeds its bound');
  }
  return Object.freeze({provingWallMilliseconds:elapsedMilliseconds(elapsed).toString(),
    peakResidentKiB:peakResidentKiB.toString()});
}
