#!/bin/bash
set -euxo pipefail

# shellcheck disable=SC1091
. "scripts/prj_vars.sh"

cfn_manage delete-stack --stack-name "$CFN_STACK_NAME_APP"
