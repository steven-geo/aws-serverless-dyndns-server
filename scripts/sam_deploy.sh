#!/bin/bash
set -euxo pipefail

# shellcheck disable=SC1091
. "scripts/prj_vars.sh"

################################################################################
# SAM Deploy
################################################################################
#    --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/infra-cfnrole-${PROJECT_ID}-nonprivileged"\

sam deploy \
    --template-file 'sam/package.yml' \
    --stack-name "$CFN_STACK_NAME_APP" \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides \
      "LogRetention"=$SAM_LOGRETENTION \
      "DDNSdomainName"="${SAM_FQDN_HOST}" \
      "HostedzoneName"="${SAM_DOMAIN_NAME}" \
      "HostedzoneId"="${SAM_DOMAIN_ID}" \
    --debug
