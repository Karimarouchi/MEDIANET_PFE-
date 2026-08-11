# Build
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn -q -DskipTests package

# Runtime
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# Docker CLI pour lancer les conteneurs de scan (Kali)
RUN apt-get update \
 && apt-get install -y --no-install-recommends docker.io ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/target/*.jar /app/app.jar

RUN mkdir -p /data/scan-results /data/vulnix-dc-cache /data/cache

ENV SPRING_PROFILES_ACTIVE=prod
ENV JAVA_OPTS="-Xms256m -Xmx1024m"

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/api/hello || exit 1

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]
