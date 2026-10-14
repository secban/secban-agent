#!/bin/bash
set -ex

REPO=$(git rev-parse --show-toplevel)


rm -rf build
mkdir -p build

BUILD_OPTIONS="-buildvcs=false -trimpath"
LDFLAGS="-ldflags=-w -s"

export GOOS="linux"
ARCHS="amd64 arm64"

TMPDIR=$(mktemp -d)

# shellcheck disable=SC2086 # We want $BUILD_OPTIONS to be expanded as-is.
for target in $ARCHS; do
    
    export GOARCH="$target"; env GOOS=$GOOS GOARCH="$target" go build $BUILD_OPTIONS -o "$TMPDIR/$target/secban-agent" "$LDFLAGS" "$REPO/cmd/agent/agent.go"
    export GOARCH="$target"; env GOOS=$GOOS GOARCH="$target" go build $BUILD_OPTIONS -o "$TMPDIR/$target/secban-agent-configcheck" "$LDFLAGS" "$REPO/cmd/configcheck/configcheck.go"
    
    cp "$REPO/_scripts/install.sh" "$TMPDIR/$target/"
    cp "$REPO/config/agent.yaml" "$TMPDIR/$target/"
    cp "$REPO/config/allowlist" "$TMPDIR/$target/"
    cp -r "$REPO/config/rules.d" "$TMPDIR/$target/"
    cp "$REPO/_scripts/systemd/secban-agent.service" "$TMPDIR/$target/"

    chmod +x "$TMPDIR/$target/install.sh"

    (cd "$TMPDIR/$target" && tar -czvf "$REPO/build/secban-agent-$GOOS-$target-$1.tar.gz" ./*)
    
done

rm -rf "$TMPDIR"
