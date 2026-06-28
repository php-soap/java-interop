# Single-stage image: the fat jar is built on the host/CI with `mvn -f oracle/pom.xml package`
# (Maven cache warm in ~/.m2) BEFORE `docker build`, so the image build itself is just a copy and
# stays in the seconds range. See README.md for the two-step build.
FROM eclipse-temurin:17-jre

# curl backs the compose healthcheck (`GET /health`); install it explicitly so the probe does not
# depend on whatever the base image happens to ship.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY oracle/target/java-interop-oracle.jar /app/oracle.jar

# Keystores are mounted at runtime: `docker run -v "$PWD/certs:/certs" ...`
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/oracle.jar"]
