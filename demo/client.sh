#!/bin/bash

# raw commands to print tokens
# curl --silent http://127.0.0.1:8080/v1/meta-data/iam/security-credentials/dd.frostbiteFalls_bullwinkle
# curl -H "Metadata-Flavor: Google" 'http://127.0.0.1:8080/computeMetadata/v1/instance/service-accounts/default/token'

# without pointing at our local attaché IMDS, these should both fail
aws s3 cp --quiet s3://emissary/rocky.txt -
gcloud storage cat gs://emissary/sherman.txt


# but pointing at attaché it will work
export AWS_EC2_METADATA_SERVICE_ENDPOINT="http://127.0.0.1:8080/"
export GCE_METADATA_HOST="http://127.0.0.1:8080"

aws s3 cp --quiet s3://emissary/rocky.txt -
gcloud storage cat gs://emissary/sherman.txt
