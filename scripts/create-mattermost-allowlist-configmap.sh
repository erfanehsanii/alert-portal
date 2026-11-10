#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || -z "${1//[[:space:]]/}" || -z "${2//[[:space:]]/}" ]]; then
  echo "Usage: $0 'chat.example.com' 'https://chat.example.com'" >&2
  echo "Use exact hostnames approved by the administrator; omit paths and wildcards." >&2
  exit 2
fi

hosts="$1"
base_url="$2"
# Reject wildcard/scheme/path forms. Ports are allowed when explicitly specified.
if [[ "$hosts" == *"*"* || "$hosts" == *"://"* || "$hosts" == *"/"* || "$hosts" == *"@"* || "$hosts" == *"?"* || "$hosts" == *"#"* ]]; then
  echo "Allowlist must contain exact hostnames (optionally with ports), not URLs or wildcards." >&2
  exit 2
fi

python3 - "$hosts" "$base_url" <<'PYVALIDATE'
import sys
from urllib.parse import urlsplit
hosts, base_url = sys.argv[1], sys.argv[2]
parsed = urlsplit(base_url)
if parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username or parsed.password:
    raise SystemExit("Base URL must be an HTTPS origin without credentials, paths, query, or fragment.")
host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
port = parsed.port
key = host if port in (None, 443) else f"{host}:{port}"
allowed = {entry.strip().lower().rstrip(".") for entry in hosts.split(",") if entry.strip()}
if key not in allowed:
    raise SystemExit("Base URL host must appear exactly in the allowlist.")
PYVALIDATE

if ! command -v kubectl >/dev/null 2>&1; then
  echo "ERROR: kubectl is required." >&2
  exit 1
fi

kubectl -n alert-portal create configmap alert-portal-mattermost-config \
  --from-literal="MATTERMOST_ALLOWED_HOSTS=$hosts" \
  --from-literal="MATTERMOST_BASE_URL=$base_url" \
  --dry-run=client -o yaml | kubectl apply -f -
echo "Updated the Mattermost server allowlist and API base URL ConfigMap."