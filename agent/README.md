# Byakugan Linux Agent – log shipping

Besides host metrics and Trivy scans, the agent ships logs to `POST /api/agent/logs` (batches of 1000, duplicates ignored server-side so retries are safe).

| Source | Events |
|---|---|
| `/var/log/auth.log` (or `/var/log/secure`) sshd | `SSH_LOGIN_SUCCESS`, `SSH_LOGIN_FAILED`, `ROOT_LOGIN_DENIED` |
| same file, sudo | `SUDO_COMMAND`, `SUDO_AUTH_FAILED` |
| journald (systemd PID 1) | `SERVICE_START`, `SERVICE_STOP`, `SERVICE_RESTART` |
| nginx access log (combined format, optional trailing `request_time`) | `HTTP_REQUEST` |

Event names are defined in `log-mapping.mjs`, shared with `scripts/import-logs.mjs` and the Windows agent.

## Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `SUPAPULSE_AUTH_LOG` | first of `/var/log/auth.log`, `/var/log/secure`, `/host/var/log/...` | auth log path |
| `SUPAPULSE_NGINX_LOG` | unset (nginx off) | e.g. `/host/var/log/nginx/access.log` |
| `SUPAPULSE_JOURNAL` | on | `0` disables journald; needs `journalctl` (included in the image) |
| `SUPAPULSE_JOURNAL_DIR` | `/host/var/log/journal` if present | journal directory of the host |
| `SUPAPULSE_LOG_INTERVAL` | `30` | seconds between shipments (min 10) |
| `SUPAPULSE_STATE_DIR` | `/var/lib/byakugan-agent` | byte offsets (`log-state.json`) and journal cursor; mounted as the `agent-state` volume |
| `SUPAPULSE_LOG_BACKFILL` | off | `1` reads existing files from the start on first run (default: start at end of file; journald starts 1 h back) |
| `SUPAPULSE_HOSTNAME` | `/host/etc/hostname`, else container hostname | host name stamped on events |

Offsets are saved only after the server accepted the batch. Rotation (new inode or truncated file) restarts at offset 0; lines written to the old file between the last read and rotation are not recovered.

In the container, `auth.log` is typically `root:adm 640`: give the agent read access (e.g. `group_add` the host's `adm` gid) or it ships nothing for that file.

## Try it without a server

```bash
node agent/log-collector.mjs --dry-run /var/log/auth.log /var/log/nginx/access.log   # prints normalized events
node --test agent/log-collector.test.mjs                                               # fabricated lines, offsets and rotation
```
