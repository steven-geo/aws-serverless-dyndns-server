#!/bin/bash
set -euxo pipefail

# shellcheck disable=SC1091
. "scripts/prj_vars.sh"

################################################################################
# Install Dependencies
################################################################################
mkdir -p sam/dyndns-function/build
# only grab packages when lambda required
# pip3 install --no-cache-dir -r sam/requirements.txt -t sam/build/
cp sam/dyndns-function/*.py sam/dyndns-function/build/

################################################################################
# Lambda Package
################################################################################
sam package \
    --template-file 'sam/template.yml' \
    --output-template-file 'sam/package.yml' \
    --s3-bucket "$ARTEFACT_BUCKET" \
    --s3-prefix "$BUCKET_PREFIX"
