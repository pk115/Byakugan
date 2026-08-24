#!/usr/bin/env sh
set -eu

INSTALL_DIR="/opt/byakugan-agent"
IMAGE="${BYAKUGAN_AGENT_IMAGE:-ghcr.io/pk115/byakugan-agent:latest}"
URL=""
TOKEN=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --url) URL="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = "0" ] || { echo "Run with sudo." >&2; exit 1; }
[ -n "$URL" ] || { echo "--url is required" >&2; exit 2; }
[ "${#TOKEN}" -ge 32 ] || { echo "A valid --token is required" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "Docker is required. Install Docker Engine first." >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required." >&2; exit 1; }

mkdir -p "$INSTALL_DIR"
DOCKER_GID="$(stat -c '%g' /var/run/docker.sock 2>/dev/null || echo 0)"
cat > "$INSTALL_DIR/.env" <<EOF
BYAKUGAN_URL=$URL
BYAKUGAN_AGENT_TOKEN=$TOKEN
DOCKER_GID=$DOCKER_GID
EOF
chmod 600 "$INSTALL_DIR/.env"
cat > "$INSTALL_DIR/compose.yaml" <<EOF
services:
  agent:
    image: $IMAGE
    restart: unless-stopped
    environment:
      SUPAPULSE_URL: \${BYAKUGAN_URL}
      SUPAPULSE_AGENT_TOKEN: \${BYAKUGAN_AGENT_TOKEN}
      SUPAPULSE_AGENT_INTERVAL: 300
      SUPAPULSE_TRIVY_TARGET: /host
      TRIVY_CACHE_DIR: /tmp/trivy-cache
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /:/host:ro
      - trivy-cache:/tmp/trivy-cache
    group_add:
      - "\${DOCKER_GID}"
volumes:
  trivy-cache:
EOF
cd "$INSTALL_DIR"
docker compose pull
docker compose up -d
unset TOKEN
echo "Byakugan Agent installed. Check: cd $INSTALL_DIR && docker compose logs -f"
