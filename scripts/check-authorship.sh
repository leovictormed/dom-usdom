#!/usr/bin/env bash
# Enforce the repository's single-author publication policy.
set -Eeuo pipefail

repo="$(git rev-parse --show-toplevel)"
cd "$repo"

revision="${1:-HEAD}"
expected_email="sorenplanck@tutamail.com"
expected_name="Soren Planck"
expected_identity="$expected_name <$expected_email>"
# Immutable adoption point for the single-author publication policy on
# mainnetswap. Commits after this point must use the canonical identity below.
policy_baseline="${DOM_AUTHORSHIP_BASELINE:-fc1774a50ee4ebddb0a67d77d10f44ba5c0e7374}"
failures=0

if ! revision_commit="$(git rev-parse --verify --end-of-options "${revision}^{commit}")"; then
  echo "authorship revision is not an exact commit: $revision" >&2
  exit 1
fi
if ! baseline_commit="$(git rev-parse --verify --end-of-options "${policy_baseline}^{commit}")"; then
  echo "authorship baseline is not an exact commit: $policy_baseline" >&2
  exit 1
fi
if ! git merge-base --is-ancestor "$baseline_commit" "$revision_commit"; then
  echo "authorship policy baseline is not an ancestor of $revision: $baseline_commit" >&2
  exit 1
fi

revision_range="${baseline_commit}..${revision_commit}"
if ! commit_list="$(git rev-list "$revision_range")"; then
  echo "could not enumerate commits in authorship range" >&2
  exit 1
fi

while IFS= read -r commit; do
  [[ -z "$commit" ]] && continue
  if ! author_name="$(git show -s --format='%an' "$commit")" \
      || ! author_email="$(git show -s --format='%ae' "$commit")" \
      || ! committer_name="$(git show -s --format='%cn' "$commit")" \
      || ! committer_email="$(git show -s --format='%ce' "$commit")"; then
    echo "$commit metadata could not be read" >&2
    failures=$((failures + 1))
    continue
  fi
  if [[ "$author_email" != "$expected_email" ]]; then
    echo "$commit has an unauthorized author email: $author_email" >&2
    failures=$((failures + 1))
  fi
  if [[ "$author_name" != "$expected_name" ]]; then
    echo "$commit has an unauthorized author name: $author_name" >&2
    failures=$((failures + 1))
  fi
  if [[ "$committer_email" != "$expected_email" ]]; then
    echo "$commit has an unauthorized committer email: $committer_email" >&2
    failures=$((failures + 1))
  fi
  if [[ "$committer_name" != "$expected_name" ]]; then
    echo "$commit has an unauthorized committer name: $committer_name" >&2
    failures=$((failures + 1))
  fi

  if ! commit_message="$(git show -s --format='%B' "$commit")"; then
    echo "$commit message could not be read" >&2
    failures=$((failures + 1))
    continue
  fi
  if ! parsed_trailers="$(
      git -c trailer.separators=: interpret-trailers --parse <<<"$commit_message"
    )"; then
    echo "$commit trailers could not be parsed" >&2
    failures=$((failures + 1))
    continue
  fi

  if [[ -n "$parsed_trailers" ]]; then
    echo "$commit contains forbidden commit trailer(s): $parsed_trailers" >&2
    failures=$((failures + 1))
  fi
done <<<"$commit_list"

if [[ $failures -ne 0 ]]; then
  echo "AUTHORSHIP = FAIL ($failures violation(s))" >&2
  exit 1
fi

echo "AUTHORSHIP = PASS (Soren Planck is the sole author and committer after $baseline_commit)"
