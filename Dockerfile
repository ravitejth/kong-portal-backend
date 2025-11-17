# Development stage
FROM node:18-alpine AS development

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

EXPOSE 3000 9229

CMD ["npm", "run", "dev"]

# Production stage
FROM node:18-alpine AS production

WORKDIR /app

RUN addgroup -g 1001 -S nodejs
RUN adduser -S admin-service -u 1001

COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY --chown=admin-service:nodejs . .

USER admin-service

EXPOSE 3000

CMD ["npm", "start"]