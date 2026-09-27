#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")"

REPOSITORY="${WIFIT3_RELEASE_REPOSITORY:-yadox666/wifit3-ng}"
WORKFLOW="release.yml"
VERSION_FILE="src/wifit3/__init__.py"
CHANGELOG="CHANGELOG.md"
ASSUME_YES=false
RELEASE_EDITED=false
RELEASE_COMMITTED=false

usage() {
  echo "Usage: ./release.sh [--yes] VERSION"
  echo "Example: ./release.sh 0.3.5"
}

fail() {
  echo "Release aborted: $*" >&2
  exit 1
}

cleanup() {
  status=$?
  if [[ $status -ne 0 && "$RELEASE_EDITED" == true && "$RELEASE_COMMITTED" != true ]]; then
    git restore --staged --worktree -- "$VERSION_FILE" "$CHANGELOG" 2>/dev/null || true
  fi
  exit "$status"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes)
      ASSUME_YES=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      fail "unknown option: $1"
      ;;
    *)
      [[ -z "${VERSION:-}" ]] || fail "only one version may be supplied"
      VERSION="${1#v}"
      shift
      ;;
  esac
done

[[ -n "${VERSION:-}" ]] || {
  usage
  exit 2
}

TAG="v$VERSION"
EXPECTED_ASSETS=(
  "wifit3-linux-arm64"
  "wifit3-linux-x64"
  "wifit3-macos-universal2"
  "wifit3-windows-x64.exe"
)

require_command git
require_command gh
[[ -x .venv/bin/python ]] || fail "missing .venv; run ./start.sh first"
[[ -x .venv/bin/uv ]] || fail "missing .venv/bin/uv; install the development environment"

[[ -z "$(git status --porcelain)" ]] || fail "working tree is not clean; review and commit it first"
[[ "$(git branch --show-current)" != "" ]] || fail "detached HEAD is not releasable"
BRANCH="$(git branch --show-current)"

gh auth status >/dev/null 2>&1 || fail "GitHub CLI is not authenticated"
DEFAULT_BRANCH="$(
  gh repo view "$REPOSITORY" --json defaultBranchRef --jq '.defaultBranchRef.name'
)"
[[ "$BRANCH" == "$DEFAULT_BRANCH" ]] || {
  fail "current branch '$BRANCH' is not GitHub's default branch '$DEFAULT_BRANCH'"
}
gh workflow view "$WORKFLOW" --repo "$REPOSITORY" >/dev/null

git fetch origin --tags
[[ "$(git rev-parse HEAD)" == "$(git rev-parse "origin/$BRANCH")" ]] || {
  fail "local branch differs from origin/$BRANCH; synchronize it before releasing"
}
[[ -z "$(git tag --list "$TAG")" ]] || fail "local tag already exists: $TAG"
if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
  fail "remote tag already exists: $TAG"
fi

CURRENT_VERSION="$(
  .venv/bin/python -c 'from wifit3 import __version__; print(__version__)'
)"
.venv/bin/python - "$CURRENT_VERSION" "$VERSION" <<'PY'
import sys

from packaging.version import InvalidVersion, Version

try:
    current = Version(sys.argv[1])
    requested = Version(sys.argv[2])
except InvalidVersion as exc:
    raise SystemExit(f"Invalid release version: {exc}") from exc
if str(requested) != sys.argv[2]:
    raise SystemExit("Use the normalized PEP 440 version without a leading v")
if requested <= current:
    raise SystemExit(f"Version {requested} must be newer than {current}")
PY

echo "Repository: $REPOSITORY"
echo "Branch:     $BRANCH"
echo "Version:    $CURRENT_VERSION -> $VERSION"
echo "Tag:        $TAG"
if [[ "$ASSUME_YES" != true ]]; then
  read -r -p "Run tests, commit, tag, push, and publish this release? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || fail "cancelled"
fi

RELEASE_EDITED=true
.venv/bin/python - "$VERSION_FILE" "$VERSION" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
version = sys.argv[2]
text = path.read_text(encoding="utf-8")
updated, count = re.subn(
    r'^__version__ = "[^"]+"$',
    f'__version__ = "{version}"',
    text,
    count=1,
    flags=re.MULTILINE,
)
if count != 1:
    raise SystemExit(f"Could not update {path}")
path.write_text(updated, encoding="utf-8")
PY

if grep -q '^## Unreleased' "$CHANGELOG"; then
  .venv/bin/python - "$CHANGELOG" "$VERSION" <<'PY'
import re
import sys
from datetime import date
from pathlib import Path

path = Path(sys.argv[1])
version = sys.argv[2]
text = path.read_text(encoding="utf-8")
updated, count = re.subn(
    r"^## Unreleased(?: - \d{4}-\d{2}-\d{2})?$",
    f"## {version} - {date.today().isoformat()}",
    text,
    count=1,
    flags=re.MULTILINE,
)
if count != 1:
    raise SystemExit(f"Could not update {path}")
path.write_text(updated, encoding="utf-8")
PY
fi

.venv/bin/python -m pytest
.venv/bin/python -m ruff check src/
.venv/bin/uv lock --check
git diff --check
[[ "$(./start.sh --version)" == "wifit3 $VERSION" ]] || fail "launcher reports the wrong version"

CHANGED_PATHS="$(git status --porcelain | awk '{print $2}')"
while IFS= read -r path; do
  [[ -z "$path" || "$path" == "$VERSION_FILE" || "$path" == "$CHANGELOG" ]] || {
    fail "release checks changed an unexpected file: $path"
  }
done <<<"$CHANGED_PATHS"

git add "$VERSION_FILE"
git diff --quiet -- "$CHANGELOG" || git add "$CHANGELOG"
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks protect --staged --redact --no-banner
fi

git commit -m "chore(release): wifit3-ng $VERSION"
RELEASE_COMMITTED=true
git push origin "$BRANCH"
git tag -a "$TAG" -m "wifit3-ng $VERSION"
git push origin "$TAG"

COMMIT="$(git rev-parse HEAD)"
RUN_ID=""
for _ in {1..10}; do
  RUN_ID="$(
    gh run list --repo "$REPOSITORY" --workflow "$WORKFLOW" --limit 20 \
      --json databaseId,headSha,event \
      --jq ".[] | select(.headSha == \"$COMMIT\" and .event == \"push\") | .databaseId" \
      | awk 'NR == 1'
  )"
  [[ -n "$RUN_ID" ]] && break
  sleep 3
done

if [[ -z "$RUN_ID" ]]; then
  echo "Tag push did not enqueue the workflow; dispatching it explicitly."
  gh workflow run "$WORKFLOW" --repo "$REPOSITORY" --ref "$TAG"
  for _ in {1..10}; do
    RUN_ID="$(
      gh run list --repo "$REPOSITORY" --workflow "$WORKFLOW" --limit 20 \
        --json databaseId,headSha,event \
        --jq ".[] | select(.headSha == \"$COMMIT\" and .event == \"workflow_dispatch\") | .databaseId" \
        | awk 'NR == 1'
    )"
    [[ -n "$RUN_ID" ]] && break
    sleep 3
  done
fi

[[ -n "$RUN_ID" ]] || fail "GitHub did not create a release workflow run"
gh run watch "$RUN_ID" --repo "$REPOSITORY" --exit-status

[[ "$(gh release view "$TAG" --repo "$REPOSITORY" --json isDraft --jq '.isDraft')" == "false" ]] || {
  fail "release is still a draft"
}
ASSETS="$(gh release view "$TAG" --repo "$REPOSITORY" --json assets --jq '.assets[].name')"
for asset in "${EXPECTED_ASSETS[@]}"; do
  grep -Fxq "$asset" <<<"$ASSETS" || fail "release asset is missing: $asset"
done

RELEASE_URL="$(gh release view "$TAG" --repo "$REPOSITORY" --json url --jq '.url')"
IS_PRERELEASE="$(
  .venv/bin/python -c 'import sys; from packaging.version import Version; print(str(Version(sys.argv[1]).is_prerelease).lower())' "$VERSION"
)"
PUBLISHED_PRERELEASE="$(
  gh release view "$TAG" --repo "$REPOSITORY" --json isPrerelease --jq '.isPrerelease'
)"
[[ "$PUBLISHED_PRERELEASE" == "$IS_PRERELEASE" ]] || fail "GitHub prerelease state is incorrect"
if [[ "$IS_PRERELEASE" == false ]]; then
  LATEST_VERSION="$(
    .venv/bin/python -c 'from wifit3.updates import check_for_update; print(check_for_update().latest_version)'
  )"
  [[ "$LATEST_VERSION" == "$VERSION" ]] || {
    fail "latest-release API reports $LATEST_VERSION instead of $VERSION"
  }
fi

[[ -z "$(git status --porcelain)" ]] || fail "release completed with a dirty working tree"
echo "Published $TAG: $RELEASE_URL"
