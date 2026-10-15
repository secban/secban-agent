# SecBan Agent

SecBan Agent is the central enforcement daemon of the SecBan framework. It maintains an in-memory registry of reported suspicious activities, checks IP allowlists, enforces firewall bans via `nftables`, logs incidents to SQLite, runs custom notification scripts, and broadcasts ban events across UNIX domain sockets.

It exposes an HTTP API over a UNIX domain socket and/or TCP.

## Features

- RESTful API over UNIX domain socket or TCP
- Kernel-level IP packet filtering via `nftables`
- Configurable per-rule thresholds (count, ban duration, registry TTL, capacity)
- IP allowlisting supporting CIDR prefixes, single IPs, loopback, and RFC1918/ULA ranges
- SQLite audit persistence for banned offenders
- Debounced custom shell actions and socket IPC broadcasts (e.g. `secban-mailer`)
- Command-line configuration validator (`secban-agent-configcheck`)
- Systemd service integration

## Installation

Pre-compiled release packages are published in the GitLab package registry.

### Download and Extract

```sh
# Set target version, OS, and architecture
VERSION="v0.1.0" # replace with desired version
OS="linux"
ARCH="amd64" # or arm64

# Download archive from GitLab Generic Package Registry
curl -sSL -o "secban-agent.tar.gz" \
  "https://gitlab.com/api/v4/projects/secban%2Fsecban-agent/packages/generic/secban-agent/${VERSION}/secban-agent-${OS}-${ARCH}-${VERSION}.tar.gz"

# Extract archive
mkdir -p /tmp/secban-install
tar -xzf "secban-agent.tar.gz" -C /tmp/secban-install
cd /tmp/secban-install
```

### Install

Run the included install script as `root`:

```sh
sudo ./install.sh
```

The script performs the following steps:
1. Creates `secban` system group and `secban-agent` system user.
2. Installs daemon `/usr/sbin/secban-agent`.
3. Installs validator `/usr/bin/secban-agent-configcheck`.
4. Creates runtime directory `/var/run/secban` and database directory `/var/lib/secban`.
5. Copies default configuration to `/etc/secban/` (`agent.yaml`, `allowlist`, `rules.d/`) if not already present.
6. Installs and enables systemd service `secban-agent.service`.

### Start Service

```sh
sudo systemctl start secban-agent.service
sudo systemctl status secban-agent.service
```

## Configuration

Configuration resides in `/etc/secban/`. You can check that your changes are correct using the `secban-agent-configcheck` tool, which will try to load and validate the configuration files.

```
/etc/secban/
├── agent.yaml       # Main daemon configuration
├── allowlist        # Allowed IPs and CIDR ranges
└── rules.d/         # Rule configurations (*.yaml)
```

### Main Configuration (`agent.yaml`)

```yaml
# Listen endpoints (UNIX socket, TCP, or both)
listen_unix: "/var/run/secban/agent.sock"
# listen_tcp: "127.0.0.1:1024"

# Firewall ban backend (nft)
ban_method: "nft"

# Path to SQLite audit database (leave empty to disable DB logging)
database: "/var/lib/secban/agent.sqlite"
# database: ":memory:"  # Use in-memory database (non-persistent)
# Allowlist settings
allow_list: "/etc/secban/allowlist"
allow_local: true       # Allow 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7
allow_loopback: true    # Allow 127.0.0.0/8, ::1

# Logging level: trace, debug, info, warn, error
log_level: "info"

# Default values inherited by all rules
rules_default:
  ban_duration: "10m"
  count: 5
  max_entries: 500
  registry_ttl: "10m"
  actions: []
  sockets:
    - "/var/run/secban/mailer.sock"
```

### Rule Definitions (`rules.d/*.yaml`)

Individual rules override `rules_default` settings.

| Field | Type | Description |
|---|---|---|
| `count` | integer | Number of reported events required to trigger a ban. |
| `ban_duration` | string | Duration of firewall block (e.g. `2m`, `1h`, `24h`). |
| `registry_ttl` | string | Time-to-live for recorded events in memory before expiration. |
| `max_entries` | integer | Maximum number of tracking entries in rule registry. |
| `actions` | list of strings | Paths to executables invoked upon ban (see [Custom Actions](#custom-actions)). |
| `sockets` | list of strings | UNIX domain sockets to broadcast IPC notification messages to. |

### Custom Actions

The `actions` list accepts any executable binary or script (`.sh`, Python, Perl, compiled binaries). Custom actions execute asynchronously with a 20-second timeout whenever an IP address is banned under the rule.

#### Arguments Passed to Executables

The agent invokes each action with 3 positional command-line arguments:

1. `$1` — **IP address**: Banned IPv4 or IPv6 string (e.g. `192.0.2.100`).
2. `$2` — **Rule name**: Triggering rule identifier (e.g. `ssh`, `standard`).
3. `$3` — **Offender JSON**: Serialized JSON payload containing timestamp, incident count, and recorded event entries:
   ```json
   {
     "ip": "192.0.2.100",
     "timestamp": "2026-10-15T10:00:00Z",
     "entries": [
       {
         "timestamp": "2026-10-15T09:59:58Z",
         "message": "failed password for root"
       }
     ],
     "count": 3
   }
   ```

#### Execution Context

- Executed as unprivileged user `secban-agent` and group `secban` (no `root` privileges).
- Inherits systemd sandbox restrictions (`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`). Scripts cannot write outside permitted runtime directories.

### Allowlist (`allowlist`)

Contains one IP address or CIDR prefix per line. Comments start with `#`:

```
# Trusted admin network
198.51.100.0/24
2001:db8::/48

# Monitoring probe
203.0.113.15
```

## API Endpoints

* Note: While GET and POST methods are specified here for semantic purposes, all endpoints actually accept any HTTP methods.

### `GET /ping`

Health check endpoint to verify agent availability.

#### Request

```sh
curl --unix-socket /var/run/secban/agent.sock http://localhost/ping
```

#### Response

- **Status Code:** `200 OK`
- **Content-Type:** `application/json`
- **Body:**
  ```json
  "pong"
  ```

---

### `GET /status/{ip}`

Retrieves current status and recorded event entries for an IP address.

#### Parameters

| Name | Type | In | Required | Description |
|---|---|---|---|---|
| `ip` | string | Path | Yes | Target IP address (IPv4 or IPv6). |

#### Request

```sh
curl --unix-socket /var/run/secban/agent.sock http://localhost/status/192.0.2.10
```

#### Response

- **Status Code:** `200 OK`
- **Body:**
  ```json
  {
    "ip": "192.0.2.10",
    "timestamp": "2026-10-14T12:00:00Z",
    "entries": [
      {
        "timestamp": "2026-10-14T12:00:00Z",
        "message": "failed password for root"
      }
    ],
    "count": 1
  }
  ```

#### Errors

- **Status Code:** `400 Bad Request`
  - Returned when path is invalid or IP has no recorded offender entry.

---

### `POST /report/{ip}/{rule}`

Reports suspicious activity for an IP address under a specified rule. Increments the rule event count. When the count threshold is met or exceeded, triggers ban action.

If IP is in allowlist, report returns `200 OK` with `{"message":"ignored","rule":"ip allowed"}` and no ban is performed.

#### Parameters

| Name | Type | In | Required | Description |
|---|---|---|---|---|
| `ip` | string | Path | Yes | Offending IP address (must be valid IP). |
| `rule` | string | Path | Yes | Name of configured ban rule (e.g. `standard`, `not_found`). |
| `message` | string | Query | No | Details about incident (max 2048 characters). |

#### Request

```sh
curl -X POST --unix-socket /var/run/secban/agent.sock "http://localhost/report/192.0.2.10/ssh?message=failed_password"
```

#### Response

- **Status Code:** `200 OK`
- **Body:**
  ```json
  {
    "ip": "192.0.2.10",
    "message": "reported",
    "rule": "ssh"
  }
  ```

#### Errors

- **Status Code:** `400 Bad Request`
  - Returned when path format is invalid, message exceeds 2048 characters, IP address is invalid, or rule is not found.

---

### `POST /ban/{ip}/{rule}`

Immediately bans an IP address using specified rule configuration, bypassing event threshold count.

If IP is in allowlist, ban request is ignored and returns `200 OK` with `{"message":"ignored","rule":"ip allowed"}`.

#### Parameters

| Name | Type | In | Required | Description |
|---|---|---|---|---|
| `ip` | string | Path | Yes | IP address to ban. |
| `rule` | string | Path | Yes | Name of configured rule for ban duration, custom actions, and socket notifications. |
| `message` | string | Query | No | Context or reason for ban (max 2048 characters). |

#### Request

```sh
curl -X POST --unix-socket /var/run/secban/agent.sock "http://localhost/ban/192.0.2.10/ssh?message=manual_admin_ban"
```

#### Response

- **Status Code:** `200 OK`
- **Body:**
  ```json
  {
    "ip": "192.0.2.10",
    "message": "banned",
    "rule": "ssh"
  }
  ```

#### Errors

- **Status Code:** `400 Bad Request`
  - Returned when path format is invalid, message exceeds 2048 characters, IP address is invalid, or rule is not found.

## Examples

### 1. Rule Configuration (`/etc/secban/rules.d/ssh.yaml`)

```yaml
ssh:
  count: 3
  ban_duration: "1h"
  registry_ttl: "30m"
  max_entries: 500
  sockets:
    - "/var/run/secban/mailer.sock"
```

### 2. Manual Ban via curl

```sh
curl -X POST --unix-socket /var/run/secban/agent.sock \
  "http://localhost/ban/198.51.100.25/ssh?message=abusive_scanner"
```

### 3. Check Configuration (`secban-agent-configcheck`)

```sh
secban-agent-configcheck -config /etc/secban
```

## Security

### Network Exposure and Authentication

SecBan Agent implements no built-in authentication, TLS encryption, or authorization layer.

- Never expose the HTTP/TCP listener (`listen_tcp`) to untrusted networks or the public internet.
- Anyone able to reach the HTTP port or UNIX socket can report incidents, query IP status, or trigger immediate IP bans.
- Recommended configuration uses UNIX domain sockets (`listen_unix: /var/run/secban/agent.sock`) with standard filesystem permissions restricted to the `secban` group.
- If TCP listening is enabled, bind exclusively to internal interfaces (e.g. `127.0.0.1` or isolated management VPN) and restrict access using firewall rules or reverse proxy authentication.

### Privilege and Capability Model

SecBan Agent runs as an unprivileged system user rather than `root`:

- **Dedicated User & Group:** Service runs under user `secban-agent` and group `secban`.
- **Linux Capabilities:** Only `CAP_NET_ADMIN` is granted (via systemd `AmbientCapabilities=CAP_NET_ADMIN` and `CapabilityBoundingSet=CAP_NET_ADMIN`) to manage `nftables` rulesets and sets without full root access.
- **Filesystem Isolation:**
  - Filesystem access is locked down (`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`).
  - Write access is strictly limited to `/var/run/secban` (runtime socket) and `/var/lib/secban` (SQLite audit database).
- **Socket Permissions:** Access to `/var/run/secban/agent.sock` is controlled by membership in the `secban` group (`0770` permissions on directory). Local services reporting offenders (such as `secban-log-monitor`) must run under or belong to the `secban` group.

### Configuration File Permissions

Because `actions` permits executing arbitrary commands, the configuration directory `/etc/secban` and all files inside (`agent.yaml`, `rules.d/*.yaml`) must only be writable by `root` (e.g. `chmod 0644 /etc/secban/agent.yaml`, `chown -R root:root /etc/secban`). Unprivileged users must never have write access to configuration files, as that would permit command execution under the `secban-agent` user.





