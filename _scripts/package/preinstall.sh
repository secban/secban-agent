#!/bin/sh
set -e

if ! getent group secban >/dev/null 2>&1; then
    groupadd --system secban
fi

if ! id -u secban >/dev/null 2>&1; then
    useradd --no-create-home --system --shell /sbin/nologin --gid secban secban
fi
