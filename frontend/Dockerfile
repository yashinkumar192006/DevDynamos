# Development console image for docker-compose.
#
# Serves the Vite dev server (with the source bind-mounted in compose) so the
# stack has a working browser UI. Production deployment uses the static build
# produced by `npm run build` (see docs/deployment.md); no Node server is
# required there.
FROM node:22-alpine

WORKDIR /app

# Dependencies first for layer caching.
COPY package.json package-lock.json ./
RUN npm ci

COPY --chown=node:node . .

USER node

EXPOSE 5173

# `--host` binds all interfaces so the port can be published from the container.
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
