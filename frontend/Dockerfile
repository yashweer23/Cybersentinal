FROM node:24-slim AS dependencies
WORKDIR /app/frontend
RUN chown node:node /app/frontend
COPY --chown=node:node package.json package-lock.json ./
USER node
RUN npm ci --no-audit --no-fund
COPY --chown=node:node . .

FROM dependencies AS development
EXPOSE 8080
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "8080"]

FROM dependencies AS builder
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.30-alpine AS production
COPY nginx/cybersentinel.conf.template /etc/nginx/templates/cybersentinel.conf.template
COPY --chmod=755 nginx/start-frontend.sh /usr/local/bin/start-frontend.sh
COPY --from=builder /app/frontend/dist /usr/share/nginx/html
ENV BACKEND_UPSTREAM=backend:8000 NGINX_RESOLVER=auto
USER 101:101
EXPOSE 8080
STOPSIGNAL SIGQUIT
ENTRYPOINT ["/usr/local/bin/start-frontend.sh"]
