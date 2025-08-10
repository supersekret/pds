#!/bin/bash
export PDS_HOSTNAME=localhost:3000
export PDS_ADMIN_PASSWORD=admin123
export PDS_PROTOCOL=http

case "$1" in
  help)
    bash /app/pdsadmin/help.sh
    ;;
  account)
    shift
    # Replace https:// with http:// in the account script for local use
    sed 's|https://|http://|g' /app/pdsadmin/account.sh > /tmp/account-local.sh
    chmod +x /tmp/account-local.sh
    bash /tmp/account-local.sh "$@"
    ;;
  create-invite-code)
    sed 's|https://|http://|g' /app/pdsadmin/create-invite-code.sh > /tmp/create-invite-local.sh
    chmod +x /tmp/create-invite-local.sh
    bash /tmp/create-invite-local.sh "$@"
    ;;
  request-crawl)
    shift
    sed 's|https://|http://|g' /app/pdsadmin/request-crawl.sh > /tmp/request-crawl-local.sh
    chmod +x /tmp/request-crawl-local.sh
    bash /tmp/request-crawl-local.sh "$@"
    ;;
  *)
    echo "Usage: pdsadmin-local {help|account|create-invite-code|request-crawl} [args]"
    ;;
esac