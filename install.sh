#!/bin/sh
# Install Keep Cmd (keepcmd), the program that makes a machine a keep.
#
#   curl -fsSL https://keepcmd.com/install.sh | sh
#
# It downloads the current release for this machine from the signed release
# feed at https://keepcmd.com/releases, checks it, and installs it as
# ~/.local/bin/keepcmd (or $KEEPCMD_INSTALL_DIR/keepcmd). Nothing else is
# written, and nothing needs root.
#
# Settings (environment):
#   KEEPCMD_INSTALL_DIR  where to put keepcmd (default ~/.local/bin)
#   KEEPCMD_FEED         the feed (default https://keepcmd.com/releases);
#                        for testing, file:///… or http://localhost:…
#
# How it decides to trust what it downloads (the trust chain):
#
#   1. latest.json is a release signed with Keep Cmd's offline release key
#      (internal/release; the signed bytes carry each platform's binary
#      name, size and SHA-256). It's fetched over HTTPS from keepcmd.com.
#   2. If openssl can check Ed25519 signatures (OpenSSL 3 does; macOS's
#      LibreSSL doesn't), this script checks latest.json's signature itself,
#      against the release keys written below (KEEPCMD_TRUSTED_KEYS, the
#      same ones the binaries trust: a test in the source keeps them equal).
#   3. The binary is downloaded and its SHA-256 and size checked against the
#      signed release.
#   4. The downloaded binary checks the release too, before it's installed:
#      `keepcmd release verify` checks latest.json's signature against the
#      release keys compiled into it, and its own hash against the signed
#      entry. That's the check that always runs, with no tools beyond sh.
#
# What that proves: the binary is the one the release key signed, and it
# trusts the same keys, so every later update (`keepcmd hub update`, the
# daemon's own updates) is checked against them. What it can't prove: this
# script, the feed and the binary all come from keepcmd.com, so a first
# install trusts HTTPS and whoever controls keepcmd.com, as every
# curl-to-sh installer does. If openssl is present, step 2 holds even
# against a swapped binary, as long as this script is the one you read.
# To check by hand instead, download this file, read it, and run it.
set -eu

KEEPCMD_TRUSTED_KEYS="ed25519:3e15ffd88009d15b243b06d19d02c2ec2b65e3b3d668dd9445e37c02ac73000c"

feed=${KEEPCMD_FEED:-https://keepcmd.com/releases}
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

# 1. The signed release.
fetch "$feed/latest.json" "$tmp/latest.json" || fail "couldn't fetch $feed/latest.json"
flat=$(tr -d ' \n\r\t' <"$tmp/latest.json")
field() { printf '%s' "$flat" | sed -n "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/p"; }
signer=$(field k)
[ -n "$signer" ] || fail "latest.json isn't a signed release"
field b | b64d >"$tmp/envelope" || fail "latest.json isn't a signed release"
field s | b64d >"$tmp/sig" || fail "latest.json isn't a signed release"

trusted=no
for k in $KEEPCMD_TRUSTED_KEYS; do
  if [ "$k" = "$signer" ]; then trusted=yes; fi
done
[ "$trusted" = yes ] || fail "latest.json is signed by a key this installer doesn't trust ($signer)"

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
if command -v openssl >/dev/null 2>&1; then
  pub=${signer#ed25519:}
  # An Ed25519 public key as DER: the SubjectPublicKeyInfo prefix, then the key.
  hex2bin "302a300506032b6570032100$pub" >"$tmp/pub.der"
  if openssl pkey -pubin -inform DER -in "$tmp/pub.der" -out "$tmp/pub.pem" >/dev/null 2>&1; then
    openssl pkeyutl -verify -pubin -inkey "$tmp/pub.pem" -rawin -in "$tmp/envelope" -sigfile "$tmp/sig" >/dev/null 2>&1 ||
      fail "latest.json's signature doesn't verify: don't install this"
    say "Checked the release's signature."
  fi
fi

# 3. This platform's binary, as the signed release lists it.
env=$(tr -d '\n\r' <"$tmp/envelope")
case $env in
  *'"space":"keepcmd","kind":"release"'*) ;;
  *) fail "latest.json isn't a Keep Cmd release" ;;
esac
version=$(printf '%s' "$env" | sed -n 's/.*"body":{"version":"\([0-9][0-9.]*\)".*/\1/p')
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

# 4. The binary checks the release against the keys compiled into it.
KEEPCMD_LOG=/dev/null "$tmp/keepcmd" release verify --feed "$tmp/latest.json" --binary "$tmp/keepcmd" --platform "$plat" >"$tmp/verify" 2>&1 ||
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
  say "     network proxies here (Ubuntu), the one root step:"
  say "       sudo $dir/keepcmd hub network install"
fi
say "  Then pair your phone (Loop Cmd or Hearth Cmd):"
say "       $cmd hub pair"
