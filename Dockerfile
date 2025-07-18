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

# ----------- Production Stage -------------
FROM node:20-alpine AS production

# Create non-root user for security
RUN addgroup -S app && adduser -S app -G app
USER app

WORKDIR /app

# Copy only production node_modules and built output
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

# Expose the port the app listens on
ENV PORT=3000
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
