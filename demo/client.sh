#!/bin/bash

# raw commands to print tokens
# curl --silent http://127.0.0.1:8080/v1/meta-data/iam/security-credentials/dd.frostbiteFalls_bullwinkle
# curl -H "Metadata-Flavor: Google" 'http://127.0.0.1:8080/computeMetadata/v1/instance/service-accounts/default/token'

# without pointing at our local attaché IMDS, these should both fail
unset AWS_EC2_METADATA_SERVICE_ENDPOINT
aws s3 cp s3://emissary/rocky.txt -

# but pointing at attaché it will work
export AWS_EC2_METADATA_SERVICE_ENDPOINT="http://127.0.0.1:8080/"
aws s3 cp s3://emissary/rocky.txt -

# same thing with a GCP golang SDK, without pointing at attache it will fail
unset GCE_METADATA_HOST
./demo-runner

# with GCE's metadata server env var set at attache it works:
export GCE_METADATA_HOST="127.0.0.1:8080"
./demo-runner

