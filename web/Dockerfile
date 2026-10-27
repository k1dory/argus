# Базовые образы пришпилены по digest (см. collector/Dockerfile — как обновлять).
ARG REGISTRY=docker.io
FROM ${REGISTRY}/library/node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS build
WORKDIR /src
COPY package.json package-lock.json ./
# --ignore-scripts: postinstall-хуки зависимостей не выполняются (supply chain);
# нативные бинарники (esbuild, lightningcss, tailwind oxide) — optionalDependencies, им хуки не нужны.
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

FROM ${REGISTRY}/library/node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914
ARG APP_VERSION=dev
ENV NODE_ENV=production APP_VERSION=$APP_VERSION
# Рантайму npm не нужен, а в его vendored-зависимостях (brace-expansion, pacote, sigstore…)
# trivy находит HIGH; пакеты Alpine поднимаем до исправленных (libcrypto и т.п.).
RUN apk upgrade --no-cache \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn-*
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
