#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop secban-agent.service 2>/dev/null || true
    systemctl disable secban-agent.service 2>/dev/null || true
fi
