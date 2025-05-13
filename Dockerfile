# Final stage
FROM node:18-alpine AS runner

# Reduce image size by avoiding unnecessary packages
RUN apk add --no-cache \
    libstdc++ \
    libgcc \
    && rm -rf /var/cache/apk/*

# Set working directory with explicit permissions
WORKDIR /home/appuser/app
RUN chown -R appuser:appuser /home/appuser/app

# Create non-root user (security best practice)
RUN adduser -S appuser
USER appuser

# Copy only necessary files
COPY --from=builder /app/dist ./dist
COPY --chown=appuser:appuser package*.json ./

# Install production dependencies and clean npm cache
RUN npm ci --only=production --omit=dev && \
    npm cache clean --force

# Optional: Remove npm itself if not needed at runtime
RUN if [ -x "$(command -v npm)" ]; then npm remove --global npm; fi

# Set memory and CPU limits (prevents OOM on small instances)
ENV NODE_OPTIONS=--max-old-space-size=256

# Start the application
CMD ["node", "dist/main.js"]