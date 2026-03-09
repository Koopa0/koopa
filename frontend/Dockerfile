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

# Angular 21 SSR startup script — loads manifests before starting Express server
RUN printf '%s\n' \
  "import { ɵsetAngularAppManifest, ɵsetAngularAppEngineManifest } from '@angular/ssr';" \
  "const appManifest = await import('./dist/koopa-blog/server/angular-app-manifest.mjs');" \
  "const engineManifest = await import('./dist/koopa-blog/server/angular-app-engine-manifest.mjs');" \
  "ɵsetAngularAppManifest(appManifest.default);" \
  "ɵsetAngularAppEngineManifest(engineManifest.default);" \
  "await import('./dist/koopa-blog/server/server.mjs');" \
  > start.mjs

ENV NODE_ENV=production
ENV PORT=4000

EXPOSE 4000

CMD ["node", "start.mjs"]
