# Build stage
FROM maven:3.9-eclipse-temurin-21-alpine AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests -q

# Runtime stage
FROM eclipse-temurin:21-jre-alpine

# Security: Create non-root user
RUN addgroup -g 1000 -S appgroup && \
    adduser -u 1000 -S appuser -G appgroup

WORKDIR /app

# Security: Copy jar with correct ownership
COPY --from=build /app/target/*.jar app.jar

# Security: Set ownership
RUN chown -R appuser:appgroup /app

# Security: Use read-only filesystem by default (can be overridden in K8s)
USER appuser

# Expose HTTP port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/actuator/health || exit 1

# Run application
ENTRYPOINT ["java", \
    "-XX:+UseG1GC", \
    "-XX:MaxGCPauseMillis=20", \
    "-XX:+ParallelRefProcEnabled", \
    "-XX:G1NewSizePercent=20", \
    "-XX:G1MaxNewSizePercent=50", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-jar", "app.jar"]