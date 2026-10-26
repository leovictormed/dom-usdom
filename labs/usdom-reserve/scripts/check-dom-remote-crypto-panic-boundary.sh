#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
bp="$repo/crates/dom-crypto/src/bulletproof_bp.rs"

python3 - "$bp" <<'PY'
import pathlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
start = text.index("pub fn bp_verify_with_extra_commit(")
end = text.index("/// Public first-round points", start)
body = text[start:end]
guard = body.index("if !proof_has_valid_curve_points(proof_bytes)")
backend = body.index("let backend = backend()?")
assert guard < backend, "transcript-bound malformed proof reaches C backend"
assert "return Ok(false);" in body[guard:backend]
PY

rg -q 'bp_verify_with_extra_commit\(&commitment, &proof, b"remote-output-capsule"\)' "$bp"
rg -q 'computed\.len\(\) != 32' "$repo/crates/dom-pow/src/randomx_pool.rs"
rg -q 'total > MAX_CODEC_LOGICAL_MSG_BYTES' "$repo/crates/dom-wire/src/codec.rs"
rg -q 'proof_bytes\.len\(\).*RANGE_PROOF_SIZE|range_proof_length_is_canonical' \
  "$repo/crates/dom-crypto/src/range_proof.rs"

echo "dom-remote-crypto-panic-boundary: PASS"
