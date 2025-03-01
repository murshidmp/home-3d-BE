# --------------------------
# 1) Builder Stage
# --------------------------
    FROM node:18 AS builder

    # Create app directory
    WORKDIR /app
    
    # Copy package files and install dependencies
    COPY package*.json ./
    RUN npm install
    
    # Copy the rest of the source code
    COPY . .
    
    # Build your NestJS app (generates /dist folder)
    RUN npm run build
    
    # --------------------------
    # 2) Production Stage
    # --------------------------
    FROM node:18 AS runner
    
    # Create app directory in the final image
    WORKDIR /app
    
    # Copy only the compiled output from builder stage
    COPY --from=builder /app/dist ./dist
    
    # Copy package files (to install only runtime dependencies)
    COPY package*.json ./
    
    # Install only production dependencies
    RUN npm install --omit=dev
    
    # Expose the port that your NestJS app listens on (default is 3000)
    EXPOSE 3000
    
    # Set environment variables as needed (optional)
    # ENV NODE_ENV=production
    
    # Start the NestJS application
    CMD ["node", "dist/main.js"]
    