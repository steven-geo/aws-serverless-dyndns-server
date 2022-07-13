#!/bin/bash
set -euxo pipefail

# shellcheck disable=SC1091
. "scripts/prj_vars.sh"

aws dynamodb put-item --table-name "${CFN_STACK_NAME_APP}-db" \
    --item '{ 
        "user": {"S": "test1"},
        "pass": {"S": "test9994"},
        "ttl": {"S": "3600"},
        "host": {"S": "test1"}
      }'
