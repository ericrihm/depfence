#!/usr/bin/env bash
set -euo pipefail

# depfence PyPI publish script
# Usage: ./scripts/publish.sh [--test]
#
# Prerequisites (one-time):
#   1. Create PyPI API token at https://pypi.org/manage/account/token/
#   2. Store: security add-generic-password -s cobalt-vault -a pypi-api-token -w "pypi-YOUR-TOKEN"
#   OR configure Trusted Publishing at https://pypi.org/manage/account/publishing/
#      Owner: ericrihm, Repo: depfence, Workflow: publish.yml, Environment: pypi

REPO="testpypi"
if [[ "${1:-}" != "--test" ]]; then
    REPO="pypi"
fi

cd "$(dirname "$0")/.."

echo "[1/4] Checking version..."
VERSION=$(python3 -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")
echo "      Version: $VERSION"

echo "[2/4] Building..."
rm -f dist/depfence-"${VERSION}"*
uv run python -m build
echo "      Built: $(ls dist/depfence-"${VERSION}"*)"

echo "[3/4] Checking wheel..."
uv run twine check dist/depfence-"${VERSION}"*

echo "[4/4] Uploading to ${REPO}..."
TOKEN=$(security find-generic-password -s cobalt-vault -a pypi-api-token -w 2>/dev/null || true)
if [[ -n "$TOKEN" ]]; then
    if [[ "$REPO" == "testpypi" ]]; then
        uv run twine upload --repository testpypi -u __token__ -p "$TOKEN" dist/depfence-"${VERSION}"*
    else
        uv run twine upload -u __token__ -p "$TOKEN" dist/depfence-"${VERSION}"*
    fi
    echo "[OK] Published depfence $VERSION to $REPO"
else
    echo "[SKIP] No PyPI token in Keychain (cobalt-vault/pypi-api-token)"
    echo "       Use GitHub Actions Trusted Publishing instead:"
    echo "       gh workflow run publish.yml"
fi
