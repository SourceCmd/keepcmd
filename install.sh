#!/bin/sh
# Install Keep Cmd (keepcmd), the program that makes a machine a keep.
#
#   curl -fsSL https://keepcmd.com/install.sh | sh
#
# It downloads the current release for this machine from the signed release
# feed at https://get.keepcmd.com/releases, checks it, and installs it as
# ~/.local/bin/keepcmd (or $KEEPCMD_INSTALL_DIR/keepcmd). Nothing else is
# written, and nothing needs root. The same script is served from
# keepcmd.com (the website) and get.keepcmd.com (the feed and binaries);
# either way it fetches from get.keepcmd.com (D-406).
#
# Settings (environment):
#   KEEPCMD_INSTALL_DIR  where to put keepcmd (default ~/.local/bin)
#   KEEPCMD_FEED         the feed (default https://get.keepcmd.com/releases);
#                        for testing, file:///… or http://localhost:…
#
# How it decides to trust what it downloads (the trust chain, D-414):
#
#   1. delegations.json is signed by one of Keep Cmd's two offline root keys
#      (written below as KEEPCMD_ROOT_KEYS, the same ones the binaries
#      compile in: a test in the source keeps them equal). It names the
#      release key, among others, and the window it's good for.
#      latest.json is a release signed with that release key (the signed
#      bytes carry each platform's binary name, size and SHA-256). Both are
#      fetched over HTTPS from get.keepcmd.com. This script checks that the
#      delegations come from a root and name latest.json's signer as a
#      release key, not revoked.
#   2. If openssl can check Ed25519 signatures (OpenSSL 3 does; macOS's
#      LibreSSL doesn't), this script checks both signatures itself.
#   3. The binary is downloaded and its SHA-256 and size checked against the
#      signed release.
#   4. The downloaded binary checks the whole chain too, before it's
#      installed: `keepcmd release verify` checks the delegations against
#      the roots compiled into it, latest.json against the release keys
#      they trust now (windows and revocations included), and its own hash
#      against the signed entry. That's the check that always runs, with no
#      tools beyond sh.
#
# What that proves: the binary is the one a delegated release key signed,
# and it trusts the same roots, so every later update (`keepcmd hub
# update`, the daemon's own updates) is checked against them. What it can't prove: this
# script comes from keepcmd.com (or get.keepcmd.com), and the feed and the
# binary from get.keepcmd.com, so a first install trusts HTTPS and whoever
# controls those two sites (one owner, two GitHub Pages repos), as every
# curl-to-sh installer does. If openssl is present, step 2 holds even
# against a swapped binary, as long as this script is the one you read.
# To check by hand instead, download this file, read it, and run it.
set -eu

KEEPCMD_ROOT_KEYS="ed25519:ff3b89aed0f0ede4f42cb0d6f498a3c82c07da9ccf8072255695ae421ff0cf05 ed25519:1fb91dfda6d50934aaca60618781901fa1779d5977378fae5716aec409553e6b"

feed=${KEEPCMD_FEED:-https://get.keepcmd.com/releases}
feed=${feed%/}
dir=${KEEPCMD_INSTALL_DIR:-${HOME:?HOME is not set}/.local/bin}

say() { printf '%s\n' "$*"; }
fail() { printf 'keepcmd install: %s\n' "$*" >&2; exit 1; }

# This machine.
case $(uname -s) in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "Keep Cmd runs on Linux (and macOS later), not $(uname -s)" ;;
esac
case $(uname -m) in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "no Keep Cmd build for $(uname -m) machines" ;;
esac
plat=$os-$arch

# Tools.
if command -v curl >/dev/null 2>&1; then
  fetch() {
    case $1 in
      https://*) curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1" ;;
      *) curl -fsSL -o "$2" "$1" ;;
    esac
  }
elif command -v wget >/dev/null 2>&1; then
  fetch() {
    case $1 in
      file://*) cp "${1#file://}" "$2" ;;
      *) wget -q -O "$2" "$1" ;;
    esac
  }
else
  fail "needs curl or wget"
fi
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
elif command -v openssl >/dev/null 2>&1; then
  sha256() { openssl dgst -sha256 -r "$1" | cut -d' ' -f1; }
else
  fail "needs sha256sum, shasum or openssl"
fi
if printf 'YQ==' | base64 -d >/dev/null 2>&1; then
  b64d() { base64 -d; }
elif printf 'YQ==' | base64 -D >/dev/null 2>&1; then
  b64d() { base64 -D; }
elif command -v openssl >/dev/null 2>&1; then
  b64d() { openssl base64 -d -A; }
else
  fail "needs base64 or openssl"
fi

case $feed in
  https://*) ;;
  *) say "Note: fetching from $feed, not over HTTPS (the signature checks still apply)." ;;
esac

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t keepcmd)
trap 'rm -rf "$tmp"' EXIT INT TERM

# 1. The delegations, then the signed release.
fetch "$feed/delegations.json" "$tmp/delegations.json" || fail "couldn't fetch $feed/delegations.json"
fetch "$feed/latest.json" "$tmp/latest.json" || fail "couldn't fetch $feed/latest.json"
field() { tr -d ' \n\r\t' <"$tmp/$1.json" | sed -n "s/.*\"$2\":\"\\([^\"]*\\)\".*/\\1/p"; }
# unpack <name>: its signer into $tmp/<name>.k, its envelope and signature
# into $tmp/<name>.env and $tmp/<name>.sig.
unpack() {
  field "$1" k >"$tmp/$1.k"
  [ -s "$tmp/$1.k" ] || fail "$1.json isn't a signed Keep Cmd file"
  field "$1" b | b64d >"$tmp/$1.env" || fail "$1.json isn't a signed Keep Cmd file"
  field "$1" s | b64d >"$tmp/$1.sig" || fail "$1.json isn't a signed Keep Cmd file"
}
unpack delegations
unpack latest
root=$(cat "$tmp/delegations.k")
signer=$(cat "$tmp/latest.k")
dels=$(tr -d '\n\r' <"$tmp/delegations.env")

trusted=no
for k in $KEEPCMD_ROOT_KEYS; do
  if [ "$k" = "$root" ]; then trusted=yes; fi
done
[ "$trusted" = yes ] || fail "delegations.json is signed by a key this installer doesn't trust ($root)"
case $dels in
  *'"space":"keepcmd","kind":"delegations"'*) ;;
  *) fail "delegations.json isn't Keep Cmd's delegations" ;;
esac
case $dels in
  *"{\"role\":\"release\",\"key\":\"$signer\""*) ;;
  *) fail "latest.json is signed by a key the delegations don't trust for releases ($signer)" ;;
esac
revoked=$(printf '%s' "$dels" | sed -n 's/.*"revoked":\[\([^]]*\)\].*/\1/p')
case $revoked in
  *"\"$signer\""*) fail "latest.json is signed by a revoked key ($signer): don't install this" ;;
esac

# 2. The signature, by this script, where openssl can.
hex2bin() {
  h=$1
  while [ -n "$h" ]; do
    rest=${h#??}
    byte=${h%"$rest"}
    # shellcheck disable=SC2059 # the octal escape is the format
    printf "\\$(printf '%03o' "0x$byte")"
    h=$rest
  done
}
# check <name> <signer id>: the file's signature, where openssl can (it
# says so with a 0 return; 1: openssl can't here).
check() {
  pub=${2#ed25519:}
  # An Ed25519 public key as DER: the SubjectPublicKeyInfo prefix, then the key.
  hex2bin "302a300506032b6570032100$pub" >"$tmp/$1.der"
  openssl pkey -pubin -inform DER -in "$tmp/$1.der" -out "$tmp/$1.pem" >/dev/null 2>&1 || return 1
  openssl pkeyutl -verify -pubin -inkey "$tmp/$1.pem" -rawin -in "$tmp/$1.env" -sigfile "$tmp/$1.sig" >/dev/null 2>&1 ||
    fail "$1.json's signature doesn't verify: don't install this"
}
if command -v openssl >/dev/null 2>&1 && check delegations "$root"; then
  check latest "$signer"
  say "Checked the release's signature."
fi

# 3. This platform's binary, as the signed release lists it.
env=$(tr -d '\n\r' <"$tmp/latest.env")
case $env in
  *'"space":"keepcmd","kind":"release"'*) ;;
  *) fail "latest.json isn't a Keep Cmd release" ;;
esac
# The manifest's format (internal/release ManifestFormat): a newer one means
# this copy of the installer is older than the feed.
format=$(printf '%s' "$env" | sed -n 's/.*"body":{"format":\([0-9][0-9]*\),.*/\1/p')
[ "$format" = 1 ] || fail "the feed's release format (${format:-none}) is newer than this installer reads: fetch the installer again from https://keepcmd.com/install.sh"
version=$(printf '%s' "$env" | sed -n 's/.*"body":{"format":[0-9]*,"version":"\([0-9][0-9.]*\)".*/\1/p')
entry=$(printf '%s' "$env" | sed -n "s/.*\"$plat\":{\\([^}]*\\)}.*/\\1/p")
[ -n "$version" ] || fail "latest.json has no version"
[ -n "$entry" ] || fail "release $version has no build for $plat"
name=$(printf '%s' "$entry" | sed -n 's/.*"name":"\([A-Za-z0-9._-]*\)".*/\1/p')
want=$(printf '%s' "$entry" | sed -n 's/.*"sha256":"\([0-9a-f]\{64\}\)".*/\1/p')
size=$(printf '%s' "$entry" | sed -n 's/.*"size":\([0-9][0-9]*\).*/\1/p')
case $name in
  keepcmd-*) ;;
  *) fail "release $version lists a strange file for $plat" ;;
esac
[ -n "$want" ] && [ -n "$size" ] || fail "release $version's entry for $plat is malformed"

say "Downloading Keep Cmd $version for $plat…"
fetch "$feed/$name" "$tmp/keepcmd" || fail "couldn't fetch $feed/$name"
got=$(sha256 "$tmp/keepcmd")
have=$(wc -c <"$tmp/keepcmd" | tr -d ' ')
[ "$got" = "$want" ] && [ "$have" = "$size" ] || fail "the download doesn't match the signed release: don't install it"
chmod 755 "$tmp/keepcmd"

# 4. The binary checks the chain against the roots compiled into it.
KEEPCMD_LOG=/dev/null "$tmp/keepcmd" release verify --delegations "$tmp/delegations.json" --feed "$tmp/latest.json" --binary "$tmp/keepcmd" --platform "$plat" >"$tmp/verify" 2>&1 ||
  fail "keepcmd $version refused the release: $(cat "$tmp/verify")"

# Install: only $dir/keepcmd, replaced in one step.
mkdir -p "$dir"
[ -f "$dir/keepcmd" ] && had=yes || had=no
cp "$tmp/keepcmd" "$dir/.keepcmd.install.$$"
mv -f "$dir/.keepcmd.install.$$" "$dir/keepcmd"
say "Installed Keep Cmd $version as $dir/keepcmd."
if [ "$had" = yes ]; then
  say "It replaced the keepcmd that was there. A keep running it picks this up when it restarts"
  say "(keepcmd service status); from now on, keeps update themselves."
fi

case ":$PATH:" in
  *":$dir:"*) cmd=keepcmd ;;
  *)
    cmd=$dir/keepcmd
    say ""
    say "$dir isn't on your PATH. Add it (e.g. in ~/.profile):"
    say "  export PATH=\"$dir:\$PATH\""
    ;;
esac

say ""
say "Next, make this machine your keep:"
say "  1. Set it up (its keys, and your recovery key):"
say "       $cmd hub setup"
say "  2. Run it as a service, so it's always on and updates itself:"
say "       $cmd service install"
if [ "$os" = linux ]; then
  say "     and, once, so it keeps running after you log out and starts at boot:"
  say "       sudo loginctl enable-linger $(id -un)"
  say "  3. If '$cmd hub network status' says agents can't be held to their"
  say "     network proxies here (Ubuntu), or that a firewall (ufw or firewalld)"
  say "     may keep Hearth Cmd or displays out, the one root step:"
  say "       sudo $dir/keepcmd hub network install"
  say "     It also allows the keep's local port through ufw or firewalld, from"
  say "     your local network only. Loop Cmd doesn't need it."
fi
say "  Then pair your phone with Loop Cmd, through the relay (this machine"
say "  needs to be online; the phone can be anywhere):"
say "       $cmd hub pair"
# --app takes any case; capitalised, since this script never spells the old
# lowercase binary's name (tools/releasetool/install_test.go).
say "  or with Hearth Cmd, on the same Wi-Fi:"
say "       $cmd hub pair --app Hearth"
