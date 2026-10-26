# Shared runtime-tool boundary for shell materializers. Source only from the
# checked repository path; callers select the tools and expose narrow wrappers.
pin_runtime_tool() {
  local name=$1 path parent owner mode size parent_owner parent_mode
  path=$(realpath "$(command -v "$name")")
  [[ -x $path && -f $path && ! -L $path ]]
  owner=$(stat -Lc '%u' "$path"); [[ $owner == 0 || $owner == "$(id -u)" ]]
  [[ $(stat -Lc '%h' "$path") == 1 ]]
  size=$(stat -Lc '%s' "$path"); (( size > 0 && size <= 512 * 1024 * 1024 ))
  mode=$(stat -Lc '%a' "$path"); (( (8#$mode & 8#022) == 0 ))
  parent=$(dirname "$path"); [[ $(realpath "$parent") == "$parent" ]]
  parent_owner=$(stat -Lc '%u' "$parent"); [[ $parent_owner == 0 || $parent_owner == "$(id -u)" ]]
  parent_mode=$(stat -Lc '%a' "$parent"); (( (8#$parent_mode & 8#022) == 0 ))
  printf -v "${name}_bin" '%s' "$path"
  printf -v "${name}_identity" '%s' "$(stat -Lc '%d:%i:%s:%Y:%Z' "$path")"
  printf -v "${name}_parent_identity" '%s' "$(stat -Lc '%d:%i:%u:%a' "$parent")"
  printf -v "${name}_sha256" '%s' "$(sha256sum "$path" | cut -d ' ' -f 1)"
}

assert_runtime_tool() {
  local name=$1 bin_name="${1}_bin" identity_name="${1}_identity"
  local parent_identity_name="${1}_parent_identity" sha_name="${1}_sha256" path parent
  path=${!bin_name}; parent=$(dirname "$path")
  [[ $(realpath "$parent") == "$parent" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$parent") == "${!parent_identity_name}" ]]
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]]
  [[ $(sha256sum "$path" | cut -d ' ' -f 1) == "${!sha_name}" ]]
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]]
  [[ $(stat -Lc '%d:%i:%u:%a' "$parent") == "${!parent_identity_name}" ]]
}
