FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build
RUN npm prune --omit=dev

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping ca-certificates fonts-noto-core && rm -rf /var/lib/apt/lists/* \
  && groupadd --system supapulse && useradd --system --gid supapulse --home /app supapulse
COPY --from=build --chown=supapulse:supapulse /app/node_modules ./node_modules
COPY --from=build --chown=supapulse:supapulse /app/dist-server ./dist-server
COPY --from=build --chown=supapulse:supapulse /app/dist-web ./dist-web
COPY --from=build --chown=supapulse:supapulse /app/package.json ./package.json
COPY --from=build --chown=supapulse:supapulse /app/scripts ./scripts
RUN mkdir -p /app/data && chown supapulse:supapulse /app/data
USER supapulse
EXPOSE 3000
VOLUME ["/app/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD node -e "fetch('http://127.0.0.1:3000/ready').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "dist-server/server.js"]
