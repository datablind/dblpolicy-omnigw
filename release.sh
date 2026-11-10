#!/usr/bin/env bash
# Authenticates anypoint-cli-v4 against Anypoint Platform, confirms the target
# business group and that the version in Cargo.toml is not already published,
# then runs everything needed to release this policy:
#   make setup   -- only if cargo-anypoint / the wasm target are missing
#   make build   -- compiles the wasm binary and generates asset files
#   make release -- publishes the production asset to Anypoint Exchange
#
# Usage:
#   ./release.sh              # if already authenticated, shows who you're
#                             # logged in as and asks whether to proceed with
#                             # that account or use a different one
#   ./release.sh --relogin    # skips the "proceed with this account?" question
#                             # and goes straight to choosing another account
#
# Using a different account:
#   1. This release only -- credentials live in environment variables and a
#      throwaway HOME directory, so your saved anypoint-cli-v4 login is never
#      touched and nothing is persisted.
#   2. Switch permanently -- the saved login is cleared first, then replaced.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

# anypoint-cli-v4 prints a Node "ExperimentalWarning: WASI" on every call.
export NODE_NO_WARNINGS=1

TEMP_HOME=""
cleanup() {
  if [[ -n "$TEMP_HOME" && -d "$TEMP_HOME" ]]; then
    rm -rf "$TEMP_HOME"
  fi
}
trap cleanup EXIT

# `account user describe` needs a real authenticated session to succeed, and
# reads whatever anypoint-cli-v4 already has in its own config.json -- so
# this doubles as both the "am I logged in" check and the "did the
# credentials I just entered actually work" check below. A Connected App
# session has no user profile, so `account user describe` can fail even with
# valid credentials; listing business groups is the fallback check.
already_authenticated() {
  anypoint-cli-v4 account user describe >/dev/null 2>&1 \
    || anypoint-cli-v4 account business-group list >/dev/null 2>&1
}

show_identity() {
  if ! anypoint-cli-v4 account user describe 2>/dev/null; then
    echo "(Connected App session -- no user profile available.) Business groups:"
    anypoint-cli-v4 account business-group list 2>/dev/null
  fi
}

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

# Prompts for credentials and the optional org / control plane host. Results
# are left in the AUTH_* variables below so either apply_* function can use them.
AUTH_METHOD=""
AUTH_CLIENT_ID=""
AUTH_CLIENT_SECRET=""
AUTH_USERNAME=""
AUTH_PASSWORD=""
AUTH_ORG=""
AUTH_HOST=""
prompt_credentials() {
  local choice
  echo "How do you want to authenticate to Anypoint Platform?"
  echo "  1. Connected App (client id / secret)"
  echo "  2. Username / password"
  read -r -p "Choose [1]: " choice
  choice="${choice:-1}"

  if [[ "$choice" == "2" ]]; then
    AUTH_METHOD="password"
    read -r -p "Username: " AUTH_USERNAME
    read -r -s -p "Password: " AUTH_PASSWORD
    echo
  else
    AUTH_METHOD="connected-app"
    read -r -p "Client ID: " AUTH_CLIENT_ID
    read -r -s -p "Client Secret: " AUTH_CLIENT_SECRET
    echo
  fi

  read -r -p "Business Group (organization) ID or name -- leave blank for your default org: " AUTH_ORG
  read -r -p "Control plane host -- leave blank for the US default (anypoint.mulesoft.com), e.g. eu1.anypoint.mulesoft.com for EU: " AUTH_HOST
}

# Option 1: use the credentials for this run only. anypoint-cli-v4 keeps its
# cached session/token in $HOME/Library/Preferences/..., and that cached
# session wins over ANYPOINT_* environment variables, so we point HOME at an
# empty throwaway directory. cargo/rustup and the CLI's installed plugins (the
# `pdk` commands) also locate their files via HOME, so their real locations are
# pinned first.
apply_credentials_for_this_run() {
  export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
  export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
  export XDG_DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
  TEMP_HOME="$(mktemp -d "${TMPDIR:-/tmp}/anypoint-release.XXXXXX")"
  export HOME="$TEMP_HOME"

  if [[ "$AUTH_METHOD" == "password" ]]; then
    export ANYPOINT_USERNAME="$AUTH_USERNAME"
    export ANYPOINT_PASSWORD="$AUTH_PASSWORD"
  else
    export ANYPOINT_CLIENT_ID="$AUTH_CLIENT_ID"
    export ANYPOINT_CLIENT_SECRET="$AUTH_CLIENT_SECRET"
  fi
  [[ -n "$AUTH_ORG" ]] && export ANYPOINT_ORG="$AUTH_ORG"
  [[ -n "$AUTH_HOST" ]] && export ANYPOINT_HOST="$AUTH_HOST"
  return 0
}

# Removes everything the previous account left in anypoint-cli-v4's saved
# config. `token` and `session` are the cached login; without clearing them the
# old account can keep being used even after new credentials are set.
clear_saved_login() {
  local key
  echo "==> Clearing the saved anypoint-cli-v4 login..."
  for key in client_id client_secret username password token session organization host; do
    anypoint-cli-v4 conf "$key" --delete >/dev/null 2>&1 || true
  done
}

# Option 2: replace the saved login.
apply_credentials_permanently() {
  clear_saved_login
  if [[ "$AUTH_METHOD" == "password" ]]; then
    anypoint-cli-v4 conf username "$AUTH_USERNAME"
    anypoint-cli-v4 conf password "$AUTH_PASSWORD"
  else
    anypoint-cli-v4 conf client_id "$AUTH_CLIENT_ID"
    anypoint-cli-v4 conf client_secret "$AUTH_CLIENT_SECRET"
  fi
  [[ -n "$AUTH_ORG" ]] && anypoint-cli-v4 conf organization "$AUTH_ORG"
  [[ -n "$AUTH_HOST" ]] && anypoint-cli-v4 conf host "$AUTH_HOST"
  return 0
}

authenticate() {
  local relogin="$1" use_existing=0 proceed scope

  if already_authenticated; then
    echo "==> Currently logged in to anypoint-cli-v4 as:"
    show_identity
    if [[ "$relogin" -eq 0 ]]; then
      read -r -p "Proceed with this account? [Y/n]: " proceed
      proceed="${proceed:-y}"
      [[ "$proceed" =~ ^[Yy] ]] && use_existing=1
    fi
  fi

  if [[ "$use_existing" -eq 1 ]]; then
    echo "==> Continuing with the current session."
    return 0
  fi

  echo "How do you want to use a different account?"
  echo "  1. For this release only (nothing is saved; your current login is left untouched)"
  echo "  2. Switch permanently (replaces the saved anypoint-cli-v4 login)"
  read -r -p "Choose [1]: " scope
  scope="${scope:-1}"

  prompt_credentials

  if [[ "$scope" == "2" ]]; then
    apply_credentials_permanently
  else
    apply_credentials_for_this_run
  fi

  echo "==> Verifying credentials..."
  if ! already_authenticated; then
    echo "error: authentication failed -- anypoint-cli-v4 could not log in with" >&2
    echo "       the credentials just entered. Double-check them and re-run this" >&2
    echo "       script." >&2
    exit 1
  fi
  echo "==> Authenticated:"
  show_identity
}

# ---------------------------------------------------------------------------
# Business group (group_id in Cargo.toml)
# ---------------------------------------------------------------------------

UUID_RE='^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

current_group_id() {
  sed -nE 's/^[[:space:]]*group_id[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' Cargo.toml | head -n 1
}

set_group_id() {
  local new_id="$1" tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/cargo-toml.XXXXXX")"
  sed -E "s/^([[:space:]]*group_id[[:space:]]*=[[:space:]]*)\"[^\"]*\"/\\1\"$new_id\"/" Cargo.toml > "$tmp"
  cat "$tmp" > Cargo.toml
  rm -f "$tmp"
}

# Prints "<id><TAB><name>" for every business group the logged-in account can
# see. Uses node (already required by anypoint-cli-v4) to parse the JSON.
list_business_groups() {
  anypoint-cli-v4 account business-group list -o json 2>/dev/null | node -e '
    let s = "";
    process.stdin.on("data", d => s += d).on("end", () => {
      try {
        for (const o of JSON.parse(s)) console.log(o.id + "\t" + o.name);
      } catch (e) { process.exit(1); }
    });'
}

# Confirms the group_id in Cargo.toml is the business group the user wants to
# publish to, and rewrites it if not. Exchange assets are published under this
# group, so a wrong value publishes into (or fails on) the wrong organization.
confirm_group_id() {
  local group_id in_list id name bg_ids=() bg_names=() i found_name="" answer pick

  group_id="$(current_group_id)"
  if [[ -z "$group_id" ]]; then
    echo "error: no group_id found under [package.metadata.anypoint] in Cargo.toml" >&2
    exit 1
  fi

  while IFS=$'\t' read -r id name; do
    [[ -z "$id" ]] && continue
    bg_ids+=("$id")
    bg_names+=("$name")
  done < <(list_business_groups || true)

  for ((i = 0; i < ${#bg_ids[@]}; i++)); do
    if [[ "${bg_ids[$i]}" == "$group_id" ]]; then
      found_name="${bg_names[$i]}"
    fi
  done

  if [[ -n "$found_name" ]]; then
    read -r -p "Cargo.toml group_id is $group_id ($found_name). Publish to this business group? [Y/n]: " answer
    answer="${answer:-y}"
    if [[ "$answer" =~ ^[Yy] ]]; then
      return 0
    fi
  elif [[ ${#bg_ids[@]} -gt 0 ]]; then
    echo "==> Cargo.toml group_id ($group_id) is not one of the business groups this account can access."
  else
    echo "==> Could not list this account's business groups; Cargo.toml group_id is $group_id."
    read -r -p "Publish to this group_id? [Y/n]: " answer
    answer="${answer:-y}"
    if [[ "$answer" =~ ^[Yy] ]]; then
      return 0
    fi
  fi

  if [[ ${#bg_ids[@]} -gt 0 ]]; then
    echo "Business groups available to this account:"
    for ((i = 0; i < ${#bg_ids[@]}; i++)); do
      echo "  $((i + 1)). ${bg_names[$i]} (${bg_ids[$i]})"
    done
  fi

  while true; do
    read -r -p "Enter the option number from the list above, or paste the correct group ID: " pick
    if [[ "$pick" =~ ^[0-9]+$ && "$pick" -ge 1 && "$pick" -le ${#bg_ids[@]} ]]; then
      pick="${bg_ids[$((pick - 1))]}"
    fi
    if [[ ! "$pick" =~ $UUID_RE ]]; then
      echo "That is not a valid group ID (expected a UUID like 2fffe86c-fd03-4170-a6cf-c8bda6617fa2)."
      continue
    fi
    if [[ ${#bg_ids[@]} -gt 0 ]]; then
      in_list=0
      for ((i = 0; i < ${#bg_ids[@]}; i++)); do
        [[ "${bg_ids[$i]}" == "$pick" ]] && in_list=1
      done
      if [[ "$in_list" -eq 0 ]]; then
        read -r -p "$pick is not in this account's business group list. Use it anyway? [y/N]: " answer
        [[ "${answer:-n}" =~ ^[Yy] ]] || continue
      fi
    fi
    break
  done

  set_group_id "$pick"
  echo "==> Updated group_id in Cargo.toml: $group_id -> $pick"
}

# ---------------------------------------------------------------------------
# Release version (version in Cargo.toml)
# ---------------------------------------------------------------------------

VERSION_RE='^[0-9]+\.[0-9]+\.[0-9]+$'

# Reads a top-level `key = "value"` entry from Cargo.toml (not indented, so it
# can't pick up keys from dependency tables).
cargo_value() {
  sed -nE "s/^$1[[:space:]]*=[[:space:]]*\"([^\"]*)\".*/\\1/p" Cargo.toml | head -n 1
}

set_version() {
  local new_version="$1" tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/cargo-toml.XXXXXX")"
  sed -E "s/^(version[[:space:]]*=[[:space:]]*)\"[^\"]*\"/\\1\"$new_version\"/" Cargo.toml > "$tmp"
  cat "$tmp" > Cargo.toml
  rm -f "$tmp"
}

# `exchange asset describe` exits non-zero when the asset version does not
# exist (or is not visible to this account), and prints JSON when it does.
exchange_describe_json() {
  anypoint-cli-v4 exchange asset describe "$1/$2/$3" -o json 2>/dev/null
}

# Prints every published version of an asset (one per line), taken from the
# describe output of a version known to exist.
published_versions() {
  exchange_describe_json "$1" "$2" "$3" | node -e '
    let s = "";
    process.stdin.on("data", d => s += d).on("end", () => {
      try {
        for (const v of JSON.parse(s).versions || []) console.log(v.version);
      } catch (e) { process.exit(0); }
    });' || true
}

# Reads versions on stdin and prints the highest one with the patch number
# incremented (1.8.14 -> 1.8.15); prints nothing if there are none.
next_patch_version() {
  node -e '
    const vs = require("fs").readFileSync(0, "utf8").split("\n")
      .filter(v => /^[0-9]+\.[0-9]+\.[0-9]+$/.test(v))
      .map(v => v.split(".").map(Number))
      .sort((a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2]);
    const m = vs.pop();
    if (m) console.log(m[0] + "." + m[1] + "." + (m[2] + 1));'
}

# Exchange rejects a release whose version already exists, and the definition
# and implementation assets are published with the same version. Checks both,
# and asks for a new version (written back to Cargo.toml) if either is taken.
confirm_version() {
  local group_id version definition_id implementation_id asset taken taken_first
  local suggestion new_version

  group_id="$(current_group_id)"
  version="$(cargo_value version)"
  definition_id="$(cargo_value definition_asset_id)"
  implementation_id="$(cargo_value implementation_asset_id)"
  if [[ -z "$version" || -z "$definition_id" || -z "$implementation_id" ]]; then
    echo "error: could not read version / definition_asset_id / implementation_asset_id from Cargo.toml" >&2
    exit 1
  fi

  while true; do
    taken=""
    taken_first=""
    for asset in "$definition_id" "$implementation_id"; do
      if exchange_describe_json "$group_id" "$asset" "$version" >/dev/null; then
        taken="${taken:+$taken, }$asset"
        taken_first="${taken_first:-$asset}"
      fi
    done

    if [[ -z "$taken" ]]; then
      echo "==> Version $version is not yet published to Exchange; good to release."
      return 0
    fi

    echo "==> Version $version already exists on Exchange for: $taken"
    echo "    A release with an existing version fails, so a new version is needed."
    suggestion="$({ published_versions "$group_id" "$taken_first" "$version"; echo "$version"; } | next_patch_version)"

    while true; do
      read -r -p "Enter the new version [${suggestion:-x.y.z}]: " new_version
      new_version="${new_version:-$suggestion}"
      if [[ ! "$new_version" =~ $VERSION_RE ]]; then
        echo "That is not a valid version (expected MAJOR.MINOR.PATCH, e.g. 1.8.15)."
        continue
      fi
      break
    done

    set_version "$new_version"
    echo "==> Updated version in Cargo.toml: $version -> $new_version"
    version="$new_version"
  done
}

# ---------------------------------------------------------------------------
# Build prerequisites
# ---------------------------------------------------------------------------

# The cargo-anypoint version `make setup` installs, read from the Makefile so
# the two can never drift apart.
expected_cargo_anypoint_version() {
  sed -nE 's/.*cargo-anypoint@([0-9][0-9.]*).*/\1/p' Makefile | head -n 1
}

# Lists what is missing for `make build`; prints nothing when everything is in place.
missing_prerequisites() {
  local expected installed
  expected="$(expected_cargo_anypoint_version)"

  if ! command -v cargo-anypoint >/dev/null 2>&1; then
    echo "cargo-anypoint is not installed"
  else
    installed="$(cargo anypoint --version 2>/dev/null | awk '{print $2}')"
    if [[ -n "$expected" && "$installed" != "$expected" ]]; then
      echo "cargo-anypoint is ${installed:-an unknown version}, expected $expected"
    fi
  fi

  if ! rustup target list --installed 2>/dev/null | grep -qx 'wasm32-wasip1'; then
    echo "rust target wasm32-wasip1 is not installed"
  fi
}

ensure_prerequisites() {
  local missing line
  missing="$(missing_prerequisites)"
  if [[ -z "$missing" ]]; then
    echo "==> Build prerequisites already in place (cargo-anypoint, wasm32-wasip1); skipping make setup."
    return 0
  fi

  echo "==> Missing build prerequisites:"
  while IFS= read -r line; do
    echo "      - $line"
  done <<< "$missing"
  echo "==> Running make setup..."
  make setup
}

# ---------------------------------------------------------------------------

main() {
  local relogin=0
  if [[ "${1:-}" == "--relogin" ]]; then
    relogin=1
  fi

  command -v anypoint-cli-v4 >/dev/null 2>&1 || {
    echo "error: anypoint-cli-v4 not found on PATH. Install it first:" >&2
    echo "  npm install -g anypoint-cli-v4" >&2
    exit 1
  }

  authenticate "$relogin"
  confirm_group_id
  confirm_version
  ensure_prerequisites

  echo "==> Running make build..."
  make build

  echo "==> Running make release..."
  make release

  echo "==> Done. Policy released to Anypoint Exchange."
}

# Run only when executed directly, so the functions above can be sourced and
# tested without kicking off a release.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
