#!/bin/bash
set -ex

OWNER=$(whoami)
if [ "$OWNER" != "root" ]; then
    echo "This script must be run as root"
    exit 1
fi

# Ensure our location.
OWN_DIR=$(dirname "$0")
cd "$OWN_DIR"

# Create secban group if not exists.
if ! getent group secban >/dev/null 2>&1; then
    groupadd --system secban
fi

# Create user for the secban-agent in the secban group.
if ! id -u secban-agent >/dev/null 2>&1; then
    useradd --no-create-home --system --shell /usr/sbin/nologin --gid secban secban-agent
fi

# Install the secban-agent binary.
cp "./secban-agent" "/usr/sbin/"
chmod +x "/usr/sbin/secban-agent"

# Install the secban-agent-configcheck binary.
cp "./secban-agent-configcheck" "/usr/bin/"
chmod 0755 "/usr/bin/secban-agent-configcheck"

# Create the runtime directory for secban-agent.
mkdir -p /var/run/secban
chown secban-agent:secban /var/run/secban
chmod 0770 /var/run/secban

# Create the database directory for secban-agent.
mkdir -p /var/lib/secban
chown secban-agent:secban /var/lib/secban
chmod 0770 /var/lib/secban

# Install the example agent configuration.
mkdir -p /etc/secban
if [ ! -f /etc/secban/agent.yaml ]; then
    cp "./agent.yaml" "/etc/secban/agent.yaml"
    cp "./allowlist" "/etc/secban/allowlist"
    cp -r "./rules.d" "/etc/secban/"
fi

# Install the systemd service file for the secban-agent.
cp "./secban-agent.service" "/etc/systemd/system/secban-agent.service"
systemctl daemon-reload
systemctl enable secban-agent.service