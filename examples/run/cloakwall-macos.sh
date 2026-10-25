#!/bin/sh
# Starts the Cloakwall proxy on macOS, reading the provider key from the
# Keychain so it is never stored in a file. Run by com.cloakwall.proxy.plist.
#
# Store the key once (it prompts for the value):
#   security add-generic-password -s cloakwall-upstream -a "$USER" -w

OPENAI_API_KEY="$(security find-generic-password -s cloakwall-upstream -w)" || {
    echo "cloakwall: no Keychain item 'cloakwall-upstream'; see the comment at the top" >&2
    exit 1
}
export OPENAI_API_KEY

mkdir -p "$HOME/Library/Logs/cloakwall"
exec "${CLOAKWALL_BIN:-$HOME/.local/bin/cloakwall}" serve \
    --upstream "${CLOAKWALL_UPSTREAM:-https://api.openai.com/v1}" \
    --upstream-key-env OPENAI_API_KEY \
    --restore \
    --audit-path "$HOME/Library/Logs/cloakwall/audit.log"
