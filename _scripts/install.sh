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

# Create user for secban in the secban group.
if ! id -u secban >/dev/null 2>&1; then
    useradd --no-create-home --system --shell /sbin/nologin --gid secban secban
fi

# Install the secban-agent binary.
cp "./secban-agent" "/usr/sbin/"
chmod +x "/usr/sbin/secban-agent"

# Install the secban-agent-configcheck binary.
cp "./secban-agent-configcheck" "/usr/bin/"
chmod 0755 "/usr/bin/secban-agent-configcheck"

# Create the runtime directory for secban-agent.
mkdir -p /var/run/secban
chown secban:secban /var/run/secban
chmod 0770 /var/run/secban

# Create the database directory for secban-agent.
mkdir -p /var/lib/secban
chown secban:secban /var/lib/secban
chmod 0770 /var/lib/secban

# Install the example agent configuration.
cp -ar "./etc/secban/" "/etc/secban/"

# Install systemd service.
if [ ! -z "$(which systemctl)" ]; then
    if [ ! -f /etc/systemd/system/secban-agent.service ]; then
        cp "./secban-agent.service" "/etc/systemd/system/secban-agent.service"
    fi
    systemctl daemon-reload
    systemctl enable secban-agent.service
fi

# Install OpenRC service.
if [ ! -z "$(which rc-update)" ]; then
    if [ ! -f /etc/init.d/secban-agent ]; then
        cp "./secban-agent.rc" "/etc/init.d/secban-agent"
        chmod +x "/etc/init.d/secban-agent"
    fi
    rc-update add secban-agent default
fi
