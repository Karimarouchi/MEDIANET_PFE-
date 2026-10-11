# Build context is the REPOSITORY ROOT (see docker-compose.yml): the image also carries the ML sidecars from ml/.
#   docker build -f Backend/Dockerfile -t medianet-backend .

# Build
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY Backend/pom.xml .
COPY Backend/src ./src
RUN mvn -q -Dmaven.test.skip=true package

# Runtime: Python 3.13 (the ML models are pickled with recent scikit-learn / xgboost, which need Python >= 3.11)
# + a Java 17 runtime for the Spring Boot jar.
FROM python:3.13-slim-bookworm
WORKDIR /app

# Docker CLI pour lancer les conteneurs de scan (Kali) + JRE 17
RUN apt-get update  && apt-get install -y --no-install-recommends openjdk-17-jre-headless docker.io ca-certificates curl  && rm -rf /var/lib/apt/lists/*

COPY ml/requirements-prod.txt /tmp/requirements-prod.txt
RUN python3 -m venv /opt/ml-venv \
 && /opt/ml-venv/bin/pip install --no-cache-dir -r /tmp/requirements-prod.txt

# ML sidecars called by the backend (Dockerfile.dockerignore keeps the build context to exactly these files)
COPY ml/supplychain/ /app/ml/supplychain/
COPY ml/secrets/ /app/ml/secrets/
ENV ML_DIR=/app/ml
ENV ML_PYTHON=/opt/ml-venv/bin/python

COPY --from=build /app/target/*.jar /app/app.jar

RUN mkdir -p /data/scan-results /data/vulnix-dc-cache /data/cache

ENV SPRING_PROFILES_ACTIVE=prod
ENV JAVA_OPTS="-Xms256m -Xmx1024m"

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/api/hello || exit 1

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]
