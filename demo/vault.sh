#!/bin/bash
set -e
set -u
set -o pipefail

pkill -15 vault || true
vault server -dev -dev-root-token-id=local -log-level=DEBUG &
sleep 1

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="local"

if [[ -z "$V_AWS_ACCESS_KEY" ]]; then
  echo "AWS_ACCESS_KEY must be set" >&2
  exit 1
fi
if [[ -z "$V_AWS_SECRET_KEY" ]]; then
  echo "AWS_ACCESS_KEY must be set" >&2
  exit 1
fi
if [[ -z "$V_GCP_SERVICE_ACCOUNT_JSON" ]]; then
  echo "AWS_ACCESS_KEY must be set" >&2
  exit 1
fi

vault secrets enable -path cloud-iam/aws/601427279990 aws
vault write cloud-iam/aws/601427279990/config/root access_key="$V_AWS_ACCESS_KEY" secret_key="$V_AWS_SECRET_KEY"
vault write cloud-iam/aws/601427279990/roles/frostbite-falls_bullwinkle credential_type=assumed_role role_arns="arn:aws:iam::601427279990:role/dd.frostbiteFalls_bullwinkle"

vault secrets enable -path cloud-iam/gcp/datadog-sandbox gcp
vault write cloud-iam/gcp/datadog-sandbox/config credentials="@$V_GCP_SERVICE_ACCOUNT_JSON"
vault write cloud-iam/gcp/datadog-sandbox/impersonated-account/frostbite-falls_bullwinkle service_account_email="dd-frostbite-bullwinkl-3c9e72b@datadog-sandbox.iam.gserviceaccount.com" token_scopes="https://www.googleapis.com/auth/cloud-platform" ttl="4h"

wait
