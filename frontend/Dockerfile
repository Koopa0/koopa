# Stage 1: Build
FROM node:22-alpine AS builder

WORKDIR /app

# .npmrc carries legacy-peer-deps=true so `npm ci` resolves the lockfile
# despite angular-eslint 21.4's pre-v22 @angular/cli peer range.
COPY package.json package-lock.json .npmrc ./
RUN npm ci

COPY . .
RUN npm run build

# Stage 2: Runtime (SSR)
FROM node:22-alpine AS runtime

WORKDIR /app

COPY --from=builder /app/dist/koopa-blog/ ./dist/koopa-blog/
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

RUN addgroup -S app && adduser -S app -G app

ENV NODE_ENV=production
ENV PORT=4000

USER app

EXPOSE 4000

CMD ["node", "dist/koopa-blog/server/server.mjs"]
