FROM node:24-slim AS builder

WORKDIR /app

COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund

COPY src ./src
RUN npm run build

FROM node:24-slim AS runner

# Install Python 3 and GNU binutils for Tier-2 Zero-Install binary inspection
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    python3 \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV NODE_ENV=production
ENV MCP_TOOL_RESULT_CONTENT_MODE=text-only
ENV REA_LOG_LEVEL=error

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force

COPY --from=builder /app/dist ./dist
COPY bridge ./bridge
COPY scripts ./scripts
COPY native ./native
COPY third_party ./third_party
COPY plugin.json ./plugin.json
COPY plugins ./plugins
COPY assets ./assets

ENTRYPOINT ["node", "dist/main.js"]
