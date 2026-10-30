#!/bin/bash
# shellcheck disable=SC2086 # We want $BUILD_OPTIONS to be expanded as-is.
set -ex
OWN_DIR="$(dirname "$0")"
cd "$OWN_DIR"
REPO=$(git rev-parse --show-toplevel)


rm -rf build
mkdir -p build

export GOOS="$1"
export ARCH="$2"
export VERSION="$3"

BUILD_OPTIONS="-buildvcs=false -trimpath"
LDFLAGS="-ldflags=-w -s"
LDFLAGS="$LDFLAGS -X gitlab.com/secban/secban-agent/version.Version=$VERSION"

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
chmod +x "$TMPDIR/$ARCH/install.sh"

cp "$REPO/_scripts/systemd/secban-agent.service" "$TMPDIR/$ARCH/"
chmod +x "$TMPDIR/$ARCH/secban-agent.service"

cp "$REPO/_scripts/openrc/secban-agent.rc" "$TMPDIR/$ARCH/"
chmod +x "$TMPDIR/$ARCH/secban-agent.rc"

mkdir -p "$TMPDIR/$ARCH/etc/secban"
cp -ar $REPO/config/default/* "$TMPDIR/$ARCH/etc/secban"
find "$TMPDIR/$ARCH/etc/secban" -type f -name "*.yaml" -exec sh -c 'for f; do mv "$f" "$f.default"; done' sh {} +
find "$TMPDIR/$ARCH/etc/secban" -type d -exec chmod 755 {} \;
find "$TMPDIR/$ARCH/etc/secban" -type f -exec chmod 644 {} \;

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