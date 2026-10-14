#!/bin/bash
set -ex

REPO=$(git rev-parse --show-toplevel)

rm -rf build
mkdir -p build

BUILD_OPTIONS='-trimpath'
LDFLAGS="-ldflags=-w -s"

go build "$BUILD_OPTIONS" -o "$REPO/build/secban-agent" "$LDFLAGS" "$REPO/cmd/agent/agent.go"

cp "$REPO/scripts/install.sh" "$REPO/build/"
cp "$REPO/config/agent.yaml" "$REPO/build/"
cp "$REPO/config/allowlist" "$REPO/build/"
cp -r "$REPO/config/rules.d" "$REPO/build/"
cp "$REPO/scripts/systemd/secban-agent.service" "$REPO/build/"

chmod +x "$REPO/build/install.sh"