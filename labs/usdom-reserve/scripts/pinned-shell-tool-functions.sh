# Shared runtime-tool boundary for shell materializers. Source only from the
# checked repository path; callers select the tools and expose narrow wrappers.
pin_runtime_tool() {
  local name=$1 variable_name path parent owner mode size parent_owner parent_mode
  variable_name=${name//-/_}
  path=$(realpath "$(command -v "$name")")
  [[ -x $path && -f $path && ! -L $path ]]
  owner=$(stat -Lc '%u' "$path"); [[ $owner == 0 || $owner == "$(id -u)" ]]
  [[ $(stat -Lc '%h' "$path") == 1 ]]
  size=$(stat -Lc '%s' "$path"); (( size > 0 && size <= 512 * 1024 * 1024 ))
  mode=$(stat -Lc '%a' "$path"); (( (8#$mode & 8#022) == 0 ))
  parent=$(dirname "$path"); [[ $(realpath "$parent") == "$parent" ]]
  parent_owner=$(stat -Lc '%u' "$parent"); [[ $parent_owner == 0 || $parent_owner == "$(id -u)" ]]
  parent_mode=$(stat -Lc '%a' "$parent"); (( (8#$parent_mode & 8#022) == 0 ))
  declare -g "${variable_name}_bin=$path"
  declare -g "${variable_name}_identity=$(stat -Lc '%d:%i:%s:%Y:%Z' "$path")"
  declare -g "${variable_name}_parent_identity=$(stat -Lc '%d:%i:%u:%a' "$parent")"
  declare -g "${variable_name}_sha256=$(sha256sum "$path" | cut -d ' ' -f 1)"
}

assert_runtime_tool() {
  local name=$1 variable_name bin_name identity_name parent_identity_name sha_name path parent
  variable_name=${name//-/_}
  bin_name="${variable_name}_bin"; identity_name="${variable_name}_identity"
  parent_identity_name="${variable_name}_parent_identity"; sha_name="${variable_name}_sha256"
  path=${!bin_name}; parent=$(dirname "$path")
  [[ $(realpath "$parent") == "$parent" ]] || return 1
  [[ $(stat -Lc '%d:%i:%u:%a' "$parent") == "${!parent_identity_name}" ]] || return 1
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]] || return 1
  [[ $(sha256sum "$path" | cut -d ' ' -f 1) == "${!sha_name}" ]] || return 1
  [[ $(stat -Lc '%d:%i:%s:%Y:%Z' "$path") == "${!identity_name}" ]] || return 1
  [[ $(stat -Lc '%d:%i:%u:%a' "$parent") == "${!parent_identity_name}" ]]
}
