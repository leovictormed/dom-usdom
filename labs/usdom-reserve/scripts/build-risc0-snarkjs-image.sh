#!/usr/bin/env bash
set -euo pipefail
umask 077
if (($# != 0)); then printf '%s\n' 'Usage: bash scripts/build-risc0-snarkjs-image.sh' >&2; exit 64; fi
readonly project=/home/leonardov/usdom-security-audit-20261015/implementation-dom-protocol/labs/usdom-reserve
readonly policy="$project/config/risc0-snarkjs-image-build-v1.json"
readonly package_source="$project/containers/risc0-snarkjs"
readonly private_root=/home/leonardov/usdom-mainnet-private/trusted-setup
readonly podman=/usr/bin/podman
test "$PWD" = "$project"
for command in node npm jq sha256sum stat realpath mktemp flock sync; do command -v "$command" >/dev/null; done
test -x "$podman"; test -f "$podman"; test ! -L "$podman"
test "$(uname -m)" = x86_64
node scripts/check-mainnet-toolchain.mjs >/dev/null
python3 scripts/ensure-private-directory-path.py "$private_root"
exec 9<"$private_root"
flock -n 9 || { printf '%s\n' 'Another trusted-setup image operation is active' >&2; exit 75; }
base=$(jq -er '.baseImage' "$policy"); tag=$(jq -er '.outputTag' "$policy")
integrity=$(jq -er '.snarkjsPackageIntegrity' "$policy")
test "$base" = 'docker.io/library/node@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df'
test "$tag" = 'localhost/usdom-snarkjs:0.7.6'
temporary=$(mktemp -d -p /dev/shm usdom-snarkjs-image.XXXXXXXX)
chmod 0700 "$temporary"; temporary_identity=$(stat -c '%u:%d:%i:%a' "$temporary")
cleanup(){ local status=${1:-$?}; trap - EXIT
  if test "$(stat -c '%u:%d:%i:%a' "$temporary" 2>/dev/null)" = "$temporary_identity"; then rm -rf -- "$temporary"; else status=1; fi
  exit "$status"; }
trap 'cleanup $?' EXIT; trap 'cleanup 129' HUP; trap 'cleanup 130' INT; trap 'cleanup 143' TERM
install -d -m 0700 "$temporary/rootfs/opt/snarkjs"
install -m 0600 "$package_source/package.json" "$temporary/rootfs/opt/snarkjs/package.json"
install -m 0600 "$package_source/package-lock.json" "$temporary/rootfs/opt/snarkjs/package-lock.json"

# Acquisition occurs before the image build and is fully constrained by the
# reviewed lockfile. Lifecycle scripts are disabled. The final build itself has
# no network and cannot resolve mutable dependencies.
npm ci --prefix "$temporary/rootfs/opt/snarkjs" --ignore-scripts --audit=false --fund=false
npm pack snarkjs@0.7.6 --ignore-scripts --pack-destination "$temporary" >/dev/null
tarball="$temporary/snarkjs-0.7.6.tgz"
test -f "$tarball"; test ! -L "$tarball"
actual_integrity=$(node -e "const fs=require('fs'),c=require('crypto');process.stdout.write('sha512-'+c.createHash('sha512').update(fs.readFileSync(process.argv[1])).digest('base64'))" "$tarball")
test "$actual_integrity" = "$integrity"
install -m 0444 "$tarball" "$temporary/rootfs/opt/snarkjs-package.tgz"
find "$temporary/rootfs" -type f -exec chmod a-w {} +
cat >"$temporary/Containerfile" <<EOF
FROM $base
COPY rootfs/ /
WORKDIR /opt/snarkjs
ENTRYPOINT ["node"]
EOF
chmod 0444 "$temporary/Containerfile"

# Only these two commands may use the network: the exact base pull and npm
# acquisition above. The content build and every later verification are offline.
"$podman" pull --platform=linux/amd64 "$base"
base_digest=$("$podman" image inspect --format='{{.Digest}}' "$base")
test "$base_digest" = 'sha256:e5a8dee7bc1e6a215d224a7ef8206f7e77271bc3cabd5febf2beafac0674f174'
"$podman" build --network=none --pull=never --no-cache --platform=linux/amd64 \
  --tag "$tag" --file "$temporary/Containerfile" "$temporary"
image_id=$("$podman" image inspect --format='{{.Id}}' "$tag")
[[ $image_id =~ ^sha256:[0-9a-f]{64}$ ]]
attestation=$("$podman" run --rm --pull=never --network=none --read-only \
  --userns=keep-id:uid=65532,gid=65532 --user=65532:65532 --cap-drop=ALL \
  --security-opt=no-new-privileges --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=67108864 \
  --entrypoint=node "$image_id" -e \
  "const fs=require('fs'),c=require('crypto'),p=JSON.parse(fs.readFileSync('/opt/snarkjs/package.json','utf8')),b=fs.readFileSync('/opt/snarkjs-package.tgz');process.stdout.write(JSON.stringify({nodeVersion:process.version,snarkjsVersion:p.version,snarkjsPackageIntegrity:'sha512-'+c.createHash('sha512').update(b).digest('base64'))+'\\n')")
test "$(jq -cer --arg integrity "$integrity" '.nodeVersion=="v24.19.0" and .snarkjsVersion=="0.7.6" and .snarkjsPackageIntegrity==$integrity' <<<"$attestation")" = true
jq -n --arg imageId "$image_id" --arg tag "$tag" --arg base "$base" \
  '{ok:true,imageId:$imageId,tag:$tag,baseImage:$base,networkDisabledForBuild:true,lifecycleScriptsDisabled:true}'
