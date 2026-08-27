# ----------- Build Stage -------------
FROM node:20-alpine AS builder

# Set working directory
WORKDIR /app

# Install dependencies first (leverages cached layers)
COPY package*.json ./
RUN npm ci --legacy-peer-deps

# Copy the rest of the source code
COPY . .

# Build the client & server bundles
RUN npm run build
RUN npm prune --omit=dev

# ----------- Production Stage -------------
FROM node:20-alpine AS production

# Nmap powers the optional NSE scan engine.
RUN apk add --no-cache nmap

# Create non-root user for security
RUN addgroup -S app && adduser -S app -G app

WORKDIR /app

# Copy only production node_modules and built output
COPY --chown=app:app --from=builder /app/package*.json ./
COPY --chown=app:app --from=builder /app/node_modules ./node_modules
COPY --chown=app:app --from=builder /app/dist ./dist
COPY --chown=app:app --from=builder /app/public ./public

USER app

# Expose the port the app listens on
ENV PORT=3000
ENV NODE_ENV=production
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/api/health >/dev/null || exit 1

# Start the application
CMD ["npm", "start"]
