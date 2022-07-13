#!/bin/bash

################################################################################
# Default Variables
################################################################################
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export CFN_STACK_NAME_APP="ddns-serverless-app"
export BUCKET_PREFIX="${CFN_STACK_NAME_APP}" # Name of function

# SAM CONFIGURATION
export ARTEFACT_BUCKET='SAMSTORAGEBUCKET' # s3 artefact location

# DDNS CONFIGURATION
export SAM_LOGRETENTION=7
export SAM_DOMAIN_NAME="exampleclientdomain.com"
export SAM_DOMAIN_ID="Z0000000000000"
export SAM_FQDN_HOST="dyndns.servicedomain.com"
