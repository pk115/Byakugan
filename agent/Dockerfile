FROM aquasec/trivy:0.72.0 AS trivy

FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends procps apt-utils docker.io && rm -rf /var/lib/apt/lists/*
WORKDIR /agent
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY supapulse-agent.mjs ./
USER node
CMD ["node", "supapulse-agent.mjs"]
