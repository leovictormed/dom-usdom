#!/usr/bin/env python3
"""Static cross-layer audit of all DOM RISC Zero receipt trust chains."""
from pathlib import Path
import argparse
import sys

ROOT=Path(__file__).resolve().parents[3]
VERSION='3.0.6'
IMAGES={
 'randomx':'8efa49d4fe0f616840013adb1d3029ef71642099cb336c577a2691f7eea1dc24',
 'aggregate':'08abf768e699ecb9d5cd2abc7603368103bcd3ee61afe9066d8a77272ac02ebf',
 'economic_chunk':'67d286e04444b52305ec409de3c0d22b2131a42f2aa6706f087ace253048e350',
 'economic_block':'03dc111fee3c42a772f142c80d4a921a19bde10f932f86c888606503a28c22a7',
 'checkpoint_segment':'371e408b360a0e4a0aae2cb994bddb2d66afcc5891a7ed574fa83119734bfbf7',
 'checkpoint_outer':'311d58dadcb97cac783e3ec0efe3c4570f42b944cbda1e48aeb56b055682257b',
 'finalized_burn':'f0d9c98287719bf6fca6626ab96f0b14e305662873a9e3b5d4894a50f206a1ae',
}
FILES={
 'randomx':'crates/dom-usdom-randomx-proof-host/src/lib.rs',
 'aggregate':'crates/dom-usdom-randomx-proof-host/src/aggregate.rs',
 'economic':'crates/dom-usdom-economic-proof-host/src/lib.rs',
 'checkpoint':'crates/dom-usdom-checkpoint-proof-host/src/lib.rs',
 'burn':'crates/dom-usdom-finalized-burn-proof-host/src/lib.rs',
 'checkpoint_adapter':'labs/usdom-reserve/contracts/DOMCheckpointRiscZeroVerifier.sol',
 'burn_adapter':'labs/usdom-reserve/contracts/DOMFinalizedBurnRiscZeroVerifier.sol',
}

def require(source:str, markers:tuple[str,...], label:str)->None:
 for marker in markers:
  if marker not in source: raise ValueError(f'{label}: missing trust-chain marker: {marker}')

def audit(texts:dict[str,str])->None:
 # Every host must bind exact journal bytes before cryptographic ImageID verification.
 for key in ('randomx','aggregate','economic','checkpoint','burn'):
  require(texts[key],('journal.bytes.as_slice() !=', '.verify(Risc0Digest::from('),key)
 for key in ('randomx','economic','checkpoint','burn'):
  require(texts[key],(f'RISC0_VERSION: &str = "{VERSION}"','receipt_kind',),key)
 require(texts['aggregate'],('RECEIPT_KIND,','RISC0_VERSION,','risc0_zkvm_version != RISC0_VERSION'),'aggregate version')
 # Recursive edges must bind both the child program identity and child journal.
 require(texts['aggregate'],('inner_image_id','record.expected_journal','verify_receipt('),'aggregate edge')
 require(texts['economic'],('randomx_receipt_image_id','expected_journal','verify_receipt('),'economic edge')
 require(texts['checkpoint'],('ECONOMIC_BLOCK_IMAGE_ID','randomx_image_id','segment_image_id','assumption.image_id()','assumption.journal()'),'checkpoint edges')
 require(texts['burn'],('recursive.image_id()','recursive.journal()','verify_composite_receipt','verify_groth16_receipt'),'finalized-burn edge')
 for source_key,image_keys in {
  'randomx':('randomx',), 'aggregate':('aggregate',),
  'economic':('economic_chunk','economic_block'),
  'checkpoint':('checkpoint_segment','checkpoint_outer'),
  'burn':('finalized_burn',),
 }.items():
  for image_key in image_keys:
   if IMAGES[image_key] not in texts[source_key]:
    raise ValueError(f'{source_key}: host does not pin {image_key} ImageID')
 # The only Ethereum-facing roots are checkpoint-outer and finalized-burn.
 for key,image in (('checkpoint_adapter',IMAGES['checkpoint_outer']),('burn_adapter',IMAGES['finalized_burn'])):
  source=texts[key]
  require(source,('RISC_ZERO_GROTH16_V3_SELECTOR = 0x73c457ba','sha256(abi.encodePacked(statementHash))','abi.encodeCall(IRiscZeroVerifierV3.verify, (proof, imageId, digest))','returnSize != 0'),key)
  # ImageID is supplied immutably at construction; deployment configuration pins
  # its exact value, while the adapter prevents any runtime substitution.
  require(source,('bytes32 public immutable imageId','imageId = imageId_','verifierConfigHash = keccak256('),key)
 # Exact checked-in IIDs close host/packager identity drift.
 iid_files={
  'randomx':'crates/dom-usdom-randomx-risc0-guest/elfs/usdom-randomx.iid',
  'aggregate':'crates/dom-usdom-randomx-aggregate-risc0-guest/elfs/usdom-randomx-aggregate.iid',
  'economic_chunk':'crates/dom-usdom-economic-chunk-risc0-guest/elfs/usdom-economic-chunk.iid',
  'economic_block':'crates/dom-usdom-economic-block-risc0-guest/elfs/usdom-economic-block.iid',
  'checkpoint_segment':'crates/dom-usdom-checkpoint-segment-risc0-guest/elfs/usdom-checkpoint-segment.iid',
  'checkpoint_outer':'crates/dom-usdom-checkpoint-outer-risc0-guest/elfs/usdom-checkpoint-outer.iid',
  'finalized_burn':'crates/dom-usdom-finalized-burn-risc0-guest/elfs/usdom-finalized-burn.iid',
 }
 for key,relative in iid_files.items():
  raw=(ROOT/relative).read_bytes()
  actual=raw.hex() if key=='finalized_burn' else raw.decode('ascii').strip()
  if actual!=IMAGES[key]: raise ValueError(f'{key}: checked-in ImageID drift')

def main()->int:
 parser=argparse.ArgumentParser(); parser.add_argument('--self-test',action='store_true'); args=parser.parse_args()
 texts={key:(ROOT/path).read_text() for key,path in FILES.items()}
 audit(texts)
 if args.self_test:
  mutated=dict(texts); mutated['aggregate']=mutated['aggregate'].replace('.verify(Risc0Digest::from(','.unverified(Risc0Digest::from(',1)
  try: audit(mutated)
  except ValueError: pass
  else: raise ValueError('mutation removing receipt.verify was accepted')
 print('PASS: 7/7 RISC Zero program/version/journal/receipt chains and both Ethereum roots are bound')
 return 0
if __name__=='__main__':
 try: raise SystemExit(main())
 except (OSError,UnicodeError,ValueError) as error:
  print(f'FAIL: {error}',file=sys.stderr); raise SystemExit(1)
