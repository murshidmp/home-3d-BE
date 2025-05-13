# --------------------------
# 1) Builder Stage
# --------------------------
    FROM node:18.19.0-alpine AS builder

    WORKDIR /app
    
    # Copy package files and install dependencies
    COPY package*.json ./
    RUN npm ci
    
    # Copy source code and build
    COPY . .
    RUN npm run build
    
    # --------------------------
    # 2) Production Stage
    # --------------------------
    FROM node:18.19.0-alpine AS runner
    
    # Create non-root user
    RUN adduser -S appuser
    USER appuser
    WORKDIR /home/appuser/app
    
    # Copy from builder stage
    COPY --from=builder /app/dist ./dist
    COPY --chown=appuser:appuser package*.json ./
    
    # Install production dependencies
    RUN npm ci --only=production --omit=dev
    
    # Start the app
    CMD ["node", "dist/main.js"]