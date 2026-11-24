#!/usr/bin/env bash
# publish.sh -- build an English LiteSync release and publish it for BRAT.
#
#   tools/publish.sh <upstream-version> <new-version>
#
# e.g. tools/publish.sh 0.19.0 0.19.1
#
# It downloads the upstream release, applies the patch, bumps the manifest
# version (so Obsidian's community updater never downgrades the English
# build back to the Chinese one), and publishes a GitHub release whose
# assets are main.js + manifest.json + styles.css -- which is what BRAT
# installs from.
#
# Needs: node, curl, and GITHUB_TOKEN (or GH_TOKEN) with repo scope.
set -euo pipefail
UPSTREAM="${1:?upstream version, e.g. 0.19.0}"
NEWVER="${2:?new version, e.g. 0.19.1}"
REPO="${GH_REPO:-rosielarose/litesync-en}"
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
[ -n "$TOKEN" ] || { echo "ERROR: set GITHUB_TOKEN"; exit 1; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
BASE="https://github.com/kjoner/litesync/releases/download/${UPSTREAM}"
echo "==> downloading upstream ${UPSTREAM}"
for f in main.js manifest.json styles.css; do
  curl -fsSL "${BASE}/${f}" -o "${WORK}/${f}"
done
echo "==> patching"
ACORN_PATH="${HERE}/patcher/vendor/acorn" \
  node "${HERE}/patcher/litesync_en4.js" "${WORK}/main.js" "${HERE}/patcher/table.json"
echo "==> bumping manifest to ${NEWVER}"
python3 - "${WORK}/manifest.json" "${NEWVER}" <<'EOF'
import json, sys
p, v = sys.argv[1], sys.argv[2]
m = json.load(open(p))
m["version"] = v
m["description"] = "Sync your vault with your own self-hosted LiteSync server (English-localized build)."
json.dump(m, open(p, "w"), indent="\t")
EOF
echo "==> publishing release ${NEWVER}"
RID=$(curl -fsSL -H "Authorization: token ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"tag_name\":\"${NEWVER}\",\"name\":\"${NEWVER} — English UI\",\"draft\":false,\"prerelease\":false}" \
  "https://api.github.com/repos/${REPO}/releases" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
for f in main.js manifest.json styles.css; do
  curl -fsSL -H "Authorization: token ${TOKEN}" -H "Content-Type: application/octet-stream" \
    --data-binary "@${WORK}/${f}" \
    "https://uploads.github.com/repos/${REPO}/releases/${RID}/assets?name=${f}" >/dev/null
  echo "    uploaded ${f}"
done
echo "==> done: https://github.com/${REPO}/releases/tag/${NEWVER}"
