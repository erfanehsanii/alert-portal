#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-alert-portal}"
SECRET_NAME="${SECRET_NAME:-alert-portal-mattermost-bot-token}"

if ! command -v kubectl >/dev/null 2>&1; then
  echo "ERROR: kubectl is required." >&2
  exit 1
fi
if kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" >/dev/null 2>&1; then
  echo "ERROR: Secret $NAMESPACE/$SECRET_NAME already exists; refusing to overwrite it." >&2
  exit 1
fi

read -r -s -p "Paste the Alert Portal Bot access token (input hidden): " BOT_TOKEN
echo
if [[ -z "$BOT_TOKEN" ]]; then
  unset BOT_TOKEN
  echo "ERROR: Empty Mattermost bot token." >&2
  exit 1
fi
if [[ "$BOT_TOKEN" == *$'\n'* || "$BOT_TOKEN" == *$'\r'* ]]; then
  unset BOT_TOKEN
  echo "ERROR: Token contains a newline." >&2
  exit 1
fi

# Stream the token to kubectl stdin; do not put it in command-line arguments or output.
if ! printf '%s' "$BOT_TOKEN" | kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" --from-file=token=/dev/stdin >/dev/null; then
  unset BOT_TOKEN
  echo "ERROR: Secret creation failed." >&2
  exit 1
fi
unset BOT_TOKEN
echo "Created Secret $NAMESPACE/$SECRET_NAME; keys:"
kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" -o json | python3 -c 'import json,sys; x=json.load(sys.stdin); print(sorted(x.get("data",{}).keys()))'
echo "Token value was not displayed."
