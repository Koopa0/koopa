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

ENV NODE_ENV=production
ENV PORT=4000

EXPOSE 4000

CMD ["node", "dist/koopa-blog/server/server.mjs"]
