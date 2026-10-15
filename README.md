# SecBan agent

SecBan agent is a component of the SecBan framework that handles agent-specific tasks and operations. It exposes a REST API for performing IP ban operations.

## Features

The main role of the SecBan agent is to keep track of reported suspicious activities and enforce IP bans accordingly. It can listen on either/both an HTTP endpoint or UNIX socket for incoming requests.
This means you can ban IP addresses directly using some custom logic at the frontline of your public facing interactions. Eg:
- some rules at your login form submission, like integrating Drupal's flood control
- httpd logic (with some proxy pass magic or LUA scripts for NGINX)
- PAM scripts
- Postfix greylisting
- ...

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

#### Parameters

| Name | Type | In | Required | Description |
|---|---|---|---|---|
| `ip` | string | Path | Yes | Offending IP address (must be valid IP). |
| `rule` | string | Path | Yes | Name of configured ban rule (e.g. `long`, `ban`, `short`, `ssh`). |
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
  - Returned when path format is invalid, message exceeds 2048 characters, IP address is invalid or allowlisted, or rule is not found.


