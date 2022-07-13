 #!/bin/bash
 
 # shellcheck disable=SC1091
. "scripts/prj_vars.sh"

curl --ipv4 --user test1:test9994 "https://${SAM_FQDN_HOST}/nic/update"
