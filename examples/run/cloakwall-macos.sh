#!/bin/sh
# Starts the Cloakwall proxy on macOS, reading the provider key from the
# Keychain so it is never stored in a file. Run by com.cloakwall.proxy.plist.
# __CLOAKWALL__ is replaced with the installed command's path at install time
# (launchd starts with a minimal PATH, so the full path is needed).
#
# Store the key once (it prompts for the value):
#   security add-generic-password -s cloakwall-upstream -a "$USER" -w

OPENAI_API_KEY="$(security find-generic-password -s cloakwall-upstream -w)" || {
    echo "cloakwall: no Keychain item 'cloakwall-upstream'; see the comment at the top" >&2
    exit 1
}
export OPENAI_API_KEY

mkdir -p "$HOME/Library/Logs/cloakwall"
exec "__CLOAKWALL__" serve \
    --upstream "${CLOAKWALL_UPSTREAM:-https://api.openai.com/v1}" \
    --upstream-key-env OPENAI_API_KEY \
    --restore \
    --audit-path "$HOME/Library/Logs/cloakwall/audit.log"
