# --------------------------
# 1) Builder Stage
# --------------------------
    FROM node:18-alpine AS builder

    # Install build dependencies required for native modules (if needed)
    RUN apk add --no-cache python3 make g++ 
    
    WORKDIR /app
    
    # Copy package files and install all dependencies using npm ci for reproducibility
    COPY package*.json ./
    RUN npm ci
    
    # Copy the rest of your application source code
    COPY . .
    
    # Build the NestJS app (this generates the /dist folder)
    RUN npm run build
    
    # --------------------------
    # 2) Production Stage
    # --------------------------
    FROM node:18-alpine AS runner
    
    WORKDIR /app
    
    # Copy the built app and package files from the builder stage
    COPY --from=builder /app/dist ./dist
    COPY package*.json ./
    
    # Install only production dependencies using npm ci (clean install)
    RUN npm ci --only=production
    
    # Set the NODE_ENV to production (optional, but recommended)
    ENV NODE_ENV=production
    
    # Expose the port your NestJS app listens on (default is 3000)
    EXPOSE 3000
    
    # Start the application
    CMD ["node", "dist/main.js"]
    