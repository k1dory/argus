# Базовые образы пришпилены по digest (см. collector/Dockerfile — как обновлять).
ARG REGISTRY=docker.io
FROM ${REGISTRY}/library/node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS build
WORKDIR /src
COPY package.json package-lock.json ./
# --ignore-scripts: postinstall-хуки зависимостей не выполняются (supply chain);
# нативные бинарники (esbuild, lightningcss, tailwind oxide) — optionalDependencies, им хуки не нужны.
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

FROM ${REGISTRY}/library/node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32
ARG APP_VERSION=dev
ENV NODE_ENV=production APP_VERSION=$APP_VERSION
WORKDIR /app
COPY --from=build /src/.next/standalone ./
COPY --from=build /src/.next/static ./.next/static
COPY --from=build /src/public ./public
COPY --from=build /src/node_modules/bcryptjs ./node_modules/bcryptjs
COPY --from=build /src/scripts/reset-admin-password.cjs ./reset-admin-password.cjs
# /data — auth.json и admin-password.txt (том web-auth); .next/cache — tmpfs в compose (ФС read-only).
RUN mkdir -p /data /app/.next/cache && chown node:node /data /app/.next/cache
USER node
EXPOSE 3000
ENV HOSTNAME=0.0.0.0 PORT=3000
ENTRYPOINT ["node", "server.js"]
