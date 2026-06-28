# Docker-only interop runner. The ONLY prerequisite is Docker — no host PHP, Java or Maven. Running
# everything in containers also sidesteps host-libxml C14N differences.
#
# One command:   make interop            (full suite)
#                make interop SUITE=wsse (one testsuite: wsse | attachments)

MVN_IMG  := maven:3-eclipse-temurin-17
JAR      := oracle/target/java-interop-oracle.jar

# Optional: SUITE=wsse|attachments restricts the run to one testsuite.
SUITE    :=
SUITE_ARG = $(if $(SUITE),--testsuite $(SUITE),)

.PHONY: help jar certs images up down test interop clean

help:
	@echo "Targets (Docker-only; only prerequisite is Docker):"
	@echo "  make interop [SUITE=wsse|attachments]  one command: jar -> images -> certs -> up -> test -> down"
	@echo "  make jar      build the oracle fat jar via the maven docker image (~/.m2 cached)"
	@echo "  make certs    (re)generate the shared cert material"
	@echo "  make images   build the oracle + php docker images"
	@echo "  make up       start the oracle and wait until healthy"
	@echo "  make down     stop everything and remove the compose volumes"
	@echo "  make test [SUITE=...]  run the PHPUnit suite in the php container"
	@echo "  make clean    remove the built jar and compose volumes"

jar: $(JAR)
$(JAR):
	docker run --rm -v "$(CURDIR):/app" -w /app -v "$(HOME)/.m2:/root/.m2" \
	  $(MVN_IMG) mvn -B -f oracle/pom.xml -DskipTests package

certs:
	bash certs/generate.sh

images:
	docker compose build

up:
	docker compose up -d --wait oracle

down:
	docker compose down -v

test:
	docker compose run --rm php sh -lc \
	  "composer install --no-interaction && vendor/bin/phpunit $(SUITE_ARG)"

# The one-liner a user runs. Order: jar -> images -> certs -> up -> test, always tearing down at the
# end (even on test failure) so no containers/volumes are left behind.
interop: jar images certs
	@set -e; \
	docker compose up -d --wait oracle; \
	status=0; \
	docker compose run --rm php sh -lc \
	  "composer install --no-interaction && vendor/bin/phpunit $(SUITE_ARG)" || status=$$?; \
	docker compose down -v; \
	exit $$status

clean:
	rm -f $(JAR) oracle/target/original-java-interop-oracle.jar
	docker compose down -v 2>/dev/null || true
