#!/usr/bin/env bash
set -euo pipefail
set +x
umask 077
if (($#!=1)); then echo 'usage: sign-operational-gas-relayer.sh FLOW' >&2; exit 64; fi
: "${USDOM_CONTROL_EVIDENCE_DIRECTORY:?required}"
project=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P); test "$PWD" = "$project"
evidence=$(realpath -ms "$USDOM_CONTROL_EVIDENCE_DIRECTORY")
test -d "$evidence" && test ! -L "$evidence" && test "$(stat -c '%u:%a' "$evidence")" = "$(id -u):700"
account_home=$(node -e 'const os=require("os");process.stdout.write(os.userInfo().homedir)')
relayer_role=''
flow=$1
case "$flow" in
 safe-deployment:governance|safe-deployment:reserveGuardian|safe-deployment:checkpointGuardian|safe-deployment:usdtCustody)
  role=${flow#*:}; relayer_role=safe-deployment; envelope="$evidence/safe-deployment-$role-relayer-envelope.json"; input="$evidence/safe-deployment-$role-relayer-input.json"; policy="$evidence/safe-control-deployment-relayer-policy.json"; output="$evidence/safe-deployment-$role-raw.txt" ;;
 recovery:governance|recovery:reserveGuardian|recovery:checkpointGuardian)
  role=${flow#*:}; relayer_role=recovery; : "${USDOM_SAFE_RECOVERY_RELAYER_POLICY:?required}"; envelope="$evidence/$role-recovery-envelope.json"; input="$evidence/$role-recovery-relayer-input.json"; policy=$(realpath -ms "$USDOM_SAFE_RECOVERY_RELAYER_POLICY"); output="$evidence/$role-recovery-raw-transaction.txt" ;;
 recovery-v3:[0-9]|recovery-v3:1[01])
  step=${flow#*:}; relayer_role=recovery; : "${USDOM_SAFE_RECOVERY_RELAYER_POLICY:?required}"; envelope="$evidence/recovery-v3-step-$step-relayer-envelope.json"; input="$evidence/recovery-v3-step-$step-relayer-input.json"; policy=$(realpath -ms "$USDOM_SAFE_RECOVERY_RELAYER_POLICY"); output="$evidence/recovery-v3-step-$step-relayer-raw.txt" ;;
 reserve-resume:schedule|reserve-resume:execute)
  step=${flow#*:}; relayer_role=reserve-resume; : "${USDOM_RESERVE_RESUME_RELAYER_POLICY:?required}"; envelope="$evidence/reserve-resume-$step-relayer-envelope.json"; input="$evidence/reserve-resume-$step-relayer-input.json"; policy=$(realpath -ms "$USDOM_RESERVE_RESUME_RELAYER_POLICY"); output="$evidence/reserve-resume-$step-relayer-raw.txt" ;;
 pilot-gate:execute)
  relayer_role=pilot-gate; envelope="$evidence/pilot-deposit-gate-relayer-envelope.json"; input="$evidence/pilot-deposit-gate-transaction.json"; policy="$evidence/pilot-gate-relayer-policy.json"; output="$evidence/pilot-deposit-gate-raw.txt" ;;
 pilot-gate:cancel)
  relayer_role=pilot-gate; envelope="$evidence/pilot-deposit-gate-cancel-relayer-envelope.json"; input="$evidence/pilot-deposit-gate-cancel-transaction.json"; policy="$evidence/pilot-gate-relayer-policy.json"; output="$evidence/pilot-deposit-gate-cancel-raw.txt" ;;
 pilot-gate:clear)
  relayer_role=pilot-gate; envelope="$evidence/pilot-deposit-gate-clear-relayer-envelope.json"; input="$evidence/pilot-deposit-gate-clear-transaction.json"; policy="$evidence/pilot-gate-relayer-policy.json"; output="$evidence/pilot-deposit-gate-clear-raw.txt" ;;
 redemption:0|redemption:1)
  index=${flow#*:}; relayer_role=pilot-gate; : "${USDOM_REDEMPTION_RELAYER_POLICY:?required}"; envelope="$evidence/closed-redemption-$index-relayer-envelope.json"; input="$evidence/closed-redemption-$index-relayer-input.json"; policy=$(realpath -ms "$USDOM_REDEMPTION_RELAYER_POLICY"); output="$evidence/closed-redemption-$index-raw.txt" ;;
 safe-deposit:approve|safe-deposit:deposit)
  step=${flow#*:}; relayer_role=pilot-gate; : "${USDOM_SAFE_DEPOSIT_RELAYER_POLICY:?required}"; envelope="$evidence/safe-deposit-$step-relayer-envelope.json"; input="$evidence/safe-deposit-$step-relayer-input.json"; policy=$(realpath -ms "$USDOM_SAFE_DEPOSIT_RELAYER_POLICY"); output="$evidence/safe-deposit-$step-relayer-raw.txt" ;;
 *) echo 'unsupported gas-relayer flow' >&2; exit 64;;
esac
if [[ -n $relayer_role ]]; then
 relayer_root="$account_home/.local/share/dom-usdom/mainnet-relayers/$relayer_role"; keystore="$relayer_root/relayer-keystore"; default_identity="$relayer_root/relayer-public-identity.json"
 test -f "$default_identity" && test ! -L "$default_identity" && test "$(stat -c '%u:%a:%h' "$default_identity")" = "$(id -u):600:1"
 expected=$(node scripts/read-mainnet-gas-relayer-identity.mjs "$default_identity" "$relayer_role")
 test "$expected" = "$(node -e 'const fs=require("fs"),{getAddress}=require("ethers"),v=JSON.parse(fs.readFileSync(process.argv[1]));process.stdout.write(getAddress(v.relayer))' "$policy")"
 test "$(node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));process.stdout.write(v.encryptedKeystoreSha256)' "$default_identity")" = "$(sha256sum "$keystore" | cut -d ' ' -f 1)"
fi
exec bash scripts/sign-gas-only-relayer-envelope.sh "$flow" "$envelope" "$input" "$policy" "$keystore" "$output"
