#!/usr/bin/env bash
# Shared fail-closed boundary for the two mutating Git release ceremonies.
# The caller must set git_bin, repository and git_directory first.

assert_release_git_environment() {
  local name
  for name in \
    GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
    GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_REPLACE_REF_BASE GIT_NO_REPLACE_OBJECTS \
    GIT_CONFIG_COUNT GIT_CONFIG_SYSTEM GIT_CONFIG_GLOBAL GIT_CONFIG_NOSYSTEM \
    GIT_ATTR_NOSYSTEM GIT_SHALLOW_FILE GIT_QUARANTINE_PATH \
    GIT_CEILING_DIRECTORIES GIT_DISCOVERY_ACROSS_FILESYSTEM \
    GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_AUTHOR_DATE \
    GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL GIT_COMMITTER_DATE; do
    if [[ -v $name ]]; then
      printf 'Forbidden inherited Git environment variable: %s\n' "$name" >&2
      return 1
    fi
  done
  while IFS='=' read -r name _; do
    case "$name" in
      GIT_CONFIG_KEY_*|GIT_CONFIG_VALUE_*)
        printf 'Forbidden inherited Git environment variable: %s\n' "$name" >&2
        return 1
        ;;
    esac
  done < <(env)
}

assert_canonical_git_repository() {
  local oid
  test "$("$git_bin" -C "$repository" rev-parse --is-inside-work-tree)" = true
  test "$(realpath -- "$("$git_bin" -C "$repository" rev-parse --show-toplevel)")" = "$repository"
  test "$(realpath -- "$("$git_bin" -C "$repository" rev-parse --path-format=absolute --git-common-dir)")" = "$git_directory"
  test "$(realpath -- "$("$git_bin" -C "$repository" rev-parse --path-format=absolute --git-dir)")" = "$git_directory"
  test -d "$git_directory/objects"; test ! -L "$git_directory/objects"
  test ! -L "$git_directory/index"
  test "$("$git_bin" -C "$repository" rev-parse --show-object-format)" = sha1
  oid=$("$git_bin" -C "$repository" rev-parse --verify HEAD)
  [[ $oid =~ ^[0-9a-f]{40}$ ]]
  test -z "$("$git_bin" -C "$repository" for-each-ref --format='%(refname)' refs/replace/)"
  test ! -e "$git_directory/info/grafts"
  test ! -e "$git_directory/objects/info/alternates"
  assert_no_repository_local_attributes
  assert_no_executable_git_config
  if "$git_bin" -C "$repository" config --show-origin --get-regexp '^(include|includeIf)\.' >/dev/null; then
    printf '%s\n' 'Git config includes are forbidden during a release ceremony' >&2
    return 1
  fi
}

assert_no_executable_git_config() {
  local configured status
  set +e
  configured=$("$git_bin" -C "$repository" config --show-scope --get-regexp \
    '^(core\.(fsmonitor|hooksPath|attributesFile|excludesFile)|diff\.external|diff\..*\.(command|textconv)|filter\..*\.(clean|smudge|process|required))$' 2>&1)
  status=$?
  set -e
  case "$status" in
    0) printf 'Executable or external Git configuration is forbidden: %s\n' "$configured" >&2; return 1 ;;
    1) return 0 ;;
    *) printf 'Could not inspect Git execution configuration: %s\n' "$configured" >&2; return 1 ;;
  esac
}

assert_no_repository_local_attributes() {
  if test -e "$git_directory/info/attributes" || test -L "$git_directory/info/attributes"; then
    printf '%s\n' 'Repository-local Git attributes are forbidden during a release ceremony' >&2
    return 1
  fi
}

assert_exact_git_config() {
  local key=$1 expected=$2 values
  values=$("$git_bin" -C "$repository" config --get-all "$key")
  test "$values" = "$expected"
}

assert_canonical_git_oid() {
  [[ ${1-} =~ ^[0-9a-f]{40}$ ]]
}

assert_tree_path_is_raw_file() {
  local tree=$1 path=$2 entry mode type tree_oid raw_oid
  assert_canonical_git_oid "$tree"
  entry=$("$git_bin" -C "$repository" ls-tree \
    --format='%(objectmode) %(objecttype) %(objectname)' "$tree" -- "$path")
  test -n "$entry"
  read -r mode type tree_oid <<<"$entry"
  case "$mode:$type" in 100644:blob|100755:blob) ;; *)
    printf 'Unsupported release tree entry %s %s: %s\n' "$mode" "$type" "$path" >&2
    return 1
    ;;
  esac
  assert_canonical_git_oid "$tree_oid"
  test -f "$repository/$path"; test ! -L "$repository/$path"
  raw_oid=$("$git_bin" -C "$repository" hash-object --no-filters -- "$path")
  assert_canonical_git_oid "$raw_oid"
  if test "$raw_oid" != "$tree_oid"; then
    printf 'Working bytes differ from inspected release tree: %s\n' "$path" >&2
    return 1
  fi
  assert_release_tree_path_has_no_transform "$tree" "$path"
}

pin_release_tree_tool() {
  local tree=$1 path=$2 descriptor_number=$3 entry mode type tree_oid raw_oid descriptor
  local file_type link_count owner file_mode
  assert_canonical_git_oid "$tree"
  entry=$("$git_bin" -C "$repository" ls-tree \
    --format='%(objectmode) %(objecttype) %(objectname)' "$tree" -- "$path")
  read -r mode type tree_oid <<<"$entry"
  case "$mode:$type" in 100644:blob|100755:blob) ;; *)
    printf 'Release tool is not a regular tree blob: %s\n' "$path" >&2; return 1 ;;
  esac
  assert_canonical_git_oid "$tree_oid"
  case "$descriptor_number" in
    6) exec 6<"$repository/$path"; descriptor=/proc/self/fd/6 ;;
    7) exec 7<"$repository/$path"; descriptor=/proc/self/fd/7 ;;
    *) printf 'Unsupported release tool descriptor: %s\n' "$descriptor_number" >&2; return 1 ;;
  esac
  IFS=: read -r file_type link_count owner file_mode < <(stat -Lc '%F:%h:%u:%a' "$descriptor")
  if test "$file_type" != 'regular file' || test "$link_count" != 1 \
      || test "$owner" != "$(id -u)" || (( (8#$file_mode & 8#022) != 0 )); then
    printf 'Release tool descriptor has unsafe identity: %s\n' "$path" >&2
    return 1
  fi
  raw_oid=$("$git_bin" -C "$repository" hash-object --no-filters -- "$descriptor")
  assert_canonical_git_oid "$raw_oid"
  if test "$raw_oid" != "$tree_oid"; then
    printf 'Release tool differs from inspected tree: %s\n' "$path" >&2
    return 1
  fi
}

assert_release_path_has_no_transform() {
  local path=$1
  local -a attributes
  mapfile -d '' -t attributes < <(printf '%s\0' "$path" | "$git_bin" -C "$repository" \
    check-attr --stdin -z filter working-tree-encoding)
  if ((${#attributes[@]} != 6)) \
      || test "${attributes[0]-}" != "$path" \
      || test "${attributes[1]-}" != filter \
      || test "${attributes[2]-}" != unspecified \
      || test "${attributes[3]-}" != "$path" \
      || test "${attributes[4]-}" != working-tree-encoding \
      || test "${attributes[5]-}" != unspecified; then
    printf 'Git filter or working-tree encoding applies to release path: %s\n' "$path" >&2
    return 1
  fi
}

assert_release_tree_path_has_no_transform() {
  local tree=$1 path=$2
  local -a attributes
  assert_canonical_git_oid "$tree"
  assert_no_repository_local_attributes
  mapfile -d '' -t attributes < <(printf '%s\0' "$path" | GIT_ATTR_NOSYSTEM=1 \
    "$git_bin" -c core.attributesFile=/dev/null -C "$repository" \
    check-attr --source "$tree" --stdin -z filter working-tree-encoding)
  assert_no_repository_local_attributes
  if ((${#attributes[@]} != 6)) \
      || test "${attributes[0]-}" != "$path" \
      || test "${attributes[1]-}" != filter \
      || test "${attributes[2]-}" != unspecified \
      || test "${attributes[3]-}" != "$path" \
      || test "${attributes[4]-}" != working-tree-encoding \
      || test "${attributes[5]-}" != unspecified; then
    printf 'Git filter or working-tree encoding applies in inspected release tree: %s\n' "$path" >&2
    return 1
  fi
}

assert_release_tree_has_no_transform_attributes() {
  local tree=$1 matches status
  assert_canonical_git_oid "$tree"
  set +e
  matches=$("$git_bin" -C "$repository" grep -I -n -E \
    '(^|[[:space:]])[!-]?(filter|working-tree-encoding)(=|[[:space:]]|$)' \
    "$tree" -- ':(top).gitattributes' ':(glob)**/.gitattributes' 2>&1)
  status=$?
  set -e
  case "$status" in
    0) printf 'Transforming attribute is forbidden in inspected release tree: %s\n' "$matches" >&2; return 1 ;;
    1) return 0 ;;
    *) printf 'Could not inspect release-tree attributes: %s\n' "$matches" >&2; return 1 ;;
  esac
}

assert_commit_shape() {
  local commit=$1 expected_parent=$2 expected_tree=$3 parents tree
  assert_canonical_git_oid "$commit"
  assert_canonical_git_oid "$expected_parent"
  assert_canonical_git_oid "$expected_tree"
  parents=$("$git_bin" -C "$repository" show -s --format='%P' "$commit")
  test "$parents" = "$expected_parent"
  tree=$("$git_bin" -C "$repository" show -s --format='%T' "$commit")
  test "$tree" = "$expected_tree"
}

parse_verified_git_fingerprint() {
  node --input-type=module --eval '
    import {parseGitSignatureFingerprint} from "./sdk/git-signature.mjs";
    let input="";
    for await (const chunk of process.stdin) input+=chunk;
    const fingerprint=parseGitSignatureFingerprint(input);
    if(fingerprint===null) process.exit(1);
    process.stdout.write(fingerprint);
  '
}

assert_annotated_tag_shape() {
  local tag=$1 expected_commit=$2 expected_subject=$3 metadata
  test "$("$git_bin" -C "$repository" cat-file -t "refs/tags/$tag")" = tag
  test "$("$git_bin" -C "$repository" rev-parse --verify "refs/tags/$tag^{}")" = "$expected_commit"
  metadata=$("$git_bin" -C "$repository" for-each-ref \
    --format='%(taggername) <%(taggeremail:trim)>%0a%(contents:subject)' "refs/tags/$tag")
  test "$metadata" = $'Soren Planck <sorenplanck@tutamail.com>\n'"$expected_subject"
}

rollback_release_index_and_head() {
  local expected_head=$1 restored_head=$2
  if test "$("$git_bin" -C "$repository" rev-parse --verify HEAD 2>/dev/null || true)" = "$expected_head"; then
    "$git_bin" -C "$repository" update-ref HEAD "$restored_head" "$expected_head"
  fi
  if test "$("$git_bin" -C "$repository" rev-parse --verify HEAD 2>/dev/null || true)" = "$restored_head"; then
    "$git_bin" -C "$repository" read-tree --reset "$restored_head"
  fi
}
