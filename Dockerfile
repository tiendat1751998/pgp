# Build stage
FROM maven:3.9-eclipse-temurin-21-alpine AS build
WORKDIR /app
COPY pom.xml .
# Optimize: Download dependencies first (caching)
RUN mvn dependency:go-offline -B -q
COPY src ./src
RUN mvn clean package -DskipTests -q

# Runtime stage: Use Distroless for minimal attack surface
FROM gcr.io/distroless/java21-debian12

# Metadata
LABEL maintainer="datdevops"
LABEL security.hardened="true"

WORKDIR /app

# Copy jar from build stage
COPY --from=build /app/target/*.jar app.jar

# Security: Java parameters for containers and cryptography
# 1. -Djava.security.egd=file:/dev/./urandom: Prevent entropy starvation in PGP ops
# 2. -XX:+UseContainerSupport: Ensure JVM respects Docker memory/cpu limits
# 3. -XX:MaxRAMPercentage: Better than hardcoded Xmx
# 4. -Djava.io.tmpdir=/tmp: Combined with K8s tmpfs mount
ENTRYPOINT ["java", \
    "-Djava.security.egd=file:/dev/./urandom", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75.0", \
    "-XX:+UseG1GC", \
    "-XX:MaxGCPauseMillis=20", \
    "-XX:+ParallelRefProcEnabled", \
    "-XX:+ExitOnOutOfMemoryError", \
    "-jar", "app.jar"]

# Note: Distroless doesn't have a shell, so wget healthcheck won't work.
# Recommendation: Use Spring Boot Actuator with K8s liveness/readiness probes directly.