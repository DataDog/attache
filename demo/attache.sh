#!/bin/bash
set -e
set -u
set -o pipefail

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="local"

./attache ./demo/config.yaml
