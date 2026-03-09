# Stage 1: Build
FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

# Stage 2: Runtime (SSR)
FROM node:22-alpine AS runtime

WORKDIR /app

COPY --from=builder /app/dist/koopa-blog/ ./dist/koopa-blog/
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Angular 21 SSR startup: load compiler + manifests before server
RUN printf '%s\n' \
  "import '@angular/compiler';" \
  "import { ɵsetAngularAppManifest, ɵsetAngularAppEngineManifest } from '@angular/ssr';" \
  "const { default: appManifest } = await import('./dist/koopa-blog/server/angular-app-manifest.mjs');" \
  "const { default: engineManifest } = await import('./dist/koopa-blog/server/angular-app-engine-manifest.mjs');" \
  "ɵsetAngularAppManifest(appManifest);" \
  "ɵsetAngularAppEngineManifest(engineManifest);" \
  "await import('./dist/koopa-blog/server/server.mjs');" \
  > start.mjs

ENV NODE_ENV=production
ENV PORT=4000

EXPOSE 4000

CMD ["node", "start.mjs"]
