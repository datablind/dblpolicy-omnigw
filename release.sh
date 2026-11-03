#!/usr/bin/env bash
# Authenticates anypoint-cli-v4 against Anypoint Platform (if not already
# authenticated), then runs everything needed to release this policy:
#   make setup   -- installs cargo-anypoint + llvm-cov if missing
#   make build   -- compiles the wasm binary and generates asset files
#   make release -- publishes the production asset to Anypoint Exchange
#
# Usage:
#   scripts/release.sh              # if already authenticated, shows who
#                                    # you're logged in as and asks whether
#                                    # to proceed with that account or switch
#   scripts/release.sh --relogin    # skips the "proceed with this account?"
#                                    # question and goes straight to
#                                    # re-entering credentials
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

RELOGIN=0
if [[ "${1:-}" == "--relogin" ]]; then
  RELOGIN=1
fi

command -v anypoint-cli-v4 >/dev/null 2>&1 || {
  echo "error: anypoint-cli-v4 not found on PATH. Install it first:" >&2
  echo "  npm install -g anypoint-cli-v4" >&2
  exit 1
}

# `account user describe` needs a real authenticated session to succeed, and
# reads whatever anypoint-cli-v4 already has in its own config.json -- so
# this doubles as both the "am I logged in" check and the "did the
# credentials I just entered actually work" check below.
already_authenticated() {
  anypoint-cli-v4 account user describe >/dev/null 2>&1
}

USE_EXISTING=0
if already_authenticated; then
  echo "==> Currently logged in to anypoint-cli-v4 as:"
  anypoint-cli-v4 account user describe
  if [[ "$RELOGIN" -eq 0 ]]; then
    read -r -p "Proceed with this account? [Y/n]: " PROCEED
    PROCEED="${PROCEED:-y}"
    [[ "$PROCEED" =~ ^[Yy] ]] && USE_EXISTING=1
  fi
fi

if [[ "$USE_EXISTING" -eq 1 ]]; then
  echo "==> Continuing with the current session."
else
  echo "How do you want to authenticate to Anypoint Platform?"
  echo "  1. Connected App (client id / secret)"
  echo "  2. Username / password"
  read -r -p "Choose [1]: " AUTH_CHOICE
  AUTH_CHOICE="${AUTH_CHOICE:-1}"

  if [[ "$AUTH_CHOICE" == "2" ]]; then
    read -r -p "Username: " ANYPOINT_USERNAME_INPUT
    read -r -s -p "Password: " ANYPOINT_PASSWORD_INPUT
    echo
    anypoint-cli-v4 conf username "$ANYPOINT_USERNAME_INPUT"
    anypoint-cli-v4 conf password "$ANYPOINT_PASSWORD_INPUT"
  else
    read -r -p "Client ID: " ANYPOINT_CLIENT_ID_INPUT
    read -r -s -p "Client Secret: " ANYPOINT_CLIENT_SECRET_INPUT
    echo
    anypoint-cli-v4 conf client_id "$ANYPOINT_CLIENT_ID_INPUT"
    anypoint-cli-v4 conf client_secret "$ANYPOINT_CLIENT_SECRET_INPUT"
  fi

  read -r -p "Business Group (organization) ID or name -- leave blank for your default org: " ANYPOINT_ORG_INPUT
  if [[ -n "$ANYPOINT_ORG_INPUT" ]]; then
    anypoint-cli-v4 conf organization "$ANYPOINT_ORG_INPUT"
  fi

  read -r -p "Control plane host -- leave blank for the US default (anypoint.mulesoft.com), e.g. eu1.anypoint.mulesoft.com for EU: " ANYPOINT_HOST_INPUT
  if [[ -n "$ANYPOINT_HOST_INPUT" ]]; then
    anypoint-cli-v4 conf host "$ANYPOINT_HOST_INPUT"
  fi

  echo "==> Verifying credentials..."
  if ! already_authenticated; then
    echo "error: authentication failed -- anypoint-cli-v4 account user describe" >&2
    echo "       did not succeed with the credentials just entered. Double-check" >&2
    echo "       them and re-run this script." >&2
    exit 1
  fi
  echo "==> Authenticated:"
  anypoint-cli-v4 account user describe
fi

echo "==> Running make setup (installs cargo-anypoint, llvm-cov if missing)..."
make setup

echo "==> Running make build..."
make build

echo "==> Running make release..."
make release

echo "==> Done. Policy released to Anypoint Exchange."
