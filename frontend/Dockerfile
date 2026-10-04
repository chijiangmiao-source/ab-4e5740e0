# ---- build stage ----
FROM node:20-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# ---- serve stage ----
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=20 \
    CMD wget -qO- http://127.0.0.1/health >/dev/null 2>&1 || exit 1

EXPOSE 80
