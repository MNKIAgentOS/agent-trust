# ghcr.io/mnkiagentos/mnki-mcp — the local MCP proxy as a container (stdio in; stdio command or HTTP upstream behind it).
# Built from the public repository root (see .github/workflows/docker.yml).
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json ./
COPY packages ./packages
COPY scripts ./scripts
RUN npm install --ignore-scripts && npm run build && npm prune --omit=dev

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages ./packages
ENTRYPOINT ["node", "packages/mcp/dist/main.js"]
