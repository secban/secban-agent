#!/bin/bash
# shellcheck disable=SC2086 # We want $BUILD_OPTIONS to be expanded as-is.
set -ex

REPO=$(git rev-parse --show-toplevel)


rm -rf build
mkdir -p build

BUILD_OPTIONS="-buildvcs=false -trimpath"
LDFLAGS="-ldflags=-w -s"

export GOOS="$1"
export ARCH="$2"
export VERSION="$3"

if [ -z "$GOOS" ] || [ -z "$ARCH" ] || [ -z "$VERSION" ]; then
    echo "Usage: $0 <GOOS> <ARCH> <VERSION>"
    exit 1
fi

TEST_INSTALL=false
if [ "$4" = "install" ]; then
    TEST_INSTALL=true
fi

TMPDIR=$(mktemp -d)

export GOARCH="$ARCH"; env GOOS="$GOOS" GOARCH="$ARCH" go build $BUILD_OPTIONS -o "$TMPDIR/$ARCH/secban-agent" "$LDFLAGS" "$REPO/cmd/agent/agent.go"
export GOARCH="$ARCH"; env GOOS="$GOOS" GOARCH="$ARCH" go build $BUILD_OPTIONS -o "$TMPDIR/$ARCH/secban-agent-configcheck" "$LDFLAGS" "$REPO/cmd/configcheck/configcheck.go"

cp "$REPO/_scripts/install.sh" "$TMPDIR/$ARCH/"
cp "$REPO/config/agent.yaml" "$TMPDIR/$ARCH/"
cp "$REPO/config/allowlist" "$TMPDIR/$ARCH/"
cp -r "$REPO/config/rules.d" "$TMPDIR/$ARCH/"
cp "$REPO/_scripts/systemd/secban-agent.service" "$TMPDIR/$ARCH/"

chmod +x "$TMPDIR/$ARCH/install.sh"

if [ "$TEST_INSTALL" = true ]; then
    (cd "$TMPDIR/$ARCH" && ./install.sh)
fi

(cd "$TMPDIR/$ARCH" && tar -czvf "$REPO/build/secban-agent-$GOOS-$ARCH-$VERSION.tar.gz" ./*)

if [ "$GOOS" = "linux" ] && command -v nfpm >/dev/null 2>&1; then
    export BIN_DIR="$TMPDIR/$ARCH"
    export REPO_DIR="$REPO"
    (
        cd "$REPO/_scripts/package"
        nfpm package -f nfpm.yaml -p deb -t "$REPO/build/"
        nfpm package -f nfpm.yaml -p rpm -t "$REPO/build/"
    )
fi