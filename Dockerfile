FROM node:22-slim

# Install Python 3 and GNU binutils for Tier-2 Zero-Install binary inspection
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    python3 \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
RUN npm ci --ignore-scripts

COPY src ./src
COPY bridge ./bridge
COPY scripts ./scripts
COPY native ./native
COPY third_party ./third_party
COPY plugin.json ./plugin.json
COPY plugins ./plugins
COPY assets ./assets

RUN npm run build && npm prune --omit=dev

ENV NODE_ENV=production
ENV MCP_TOOL_RESULT_CONTENT_MODE=text-only

ENTRYPOINT ["node", "dist/main.js"]
