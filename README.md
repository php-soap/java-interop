# php-soap / java-interop

Cross-stack SOAP interop tests. PHPUnit tests drive the **php-soap middlewares** and assert they
interoperate, over HTTP, with a Dockerised **Apache WSS4J** reference implementation (the "oracle").

```
PHPUnit (tests/Wsse, tests/Attachments)
        |  PHP middleware produces / consumes WS-Security messages
        v
   HTTP (INTEROP_URL, default http://127.0.0.1:8080)
        v
  java-interop-oracle  (com.sun.net.httpserver + WSS4J 3.0.4, in Docker)
```

Each direction is tested: PHP signs/encrypts and the oracle verifies/decrypts, and the oracle
signs/encrypts and the PHP middleware verifies/decrypts. Cert material is shared between both sides so
each trusts the other.

## Layout

```
oracle/                 Java HTTP oracle (Maven module, artifact java-interop-oracle)
  pom.xml
  src/main/java/org/phpsoap/interop/
    OracleServer.java    HTTP front-end (health/sign/verify/encrypt/decrypt)
    Signer/Verifier/Encryptor/Decryptor.java   WSS4J ops (reused, framework-free)
    CryptoFactory/ScenarioConfig/Xml/CallbackHandlerStub.java
Dockerfile              single-stage; copies the prebuilt jar (build is a ~seconds copy)
certs/generate.sh       pure-openssl (+keytool) CA + leaves + keystores generator (idempotent)
samples/                unsigned SOAP request fixtures
composer.json           dev tooling + path repos to the sibling middlewares
phpunit.xml.dist        one <testsuite> per feature area (wsse, attachments)
tests/
  Support/              Oracle HTTP client + InteropTestCase base
  Wsse/                 signing + encryption interop tests
  Attachments/          SwA/MTOM interop tests
.github/workflows/
  interop.yml           reusable (workflow_call) workflow consumers call from their PR CI
  ci.yml                this repo's own self-test
```

## Server endpoints

| Method + path | Body | Response |
|---|---|---|
| `GET /health` | – | `200 ok` |
| `POST /sign` | SOAP envelope | WSS4J-signed envelope (`text/xml`) |
| `POST /verify` | signed envelope | `200 {"valid":true}` or `200 {"valid":false,"reason":"..."}`; `400` only on malformed XML |
| `POST /encrypt` | envelope | WSS4J-encrypted envelope, recipient = `php-client` cert |
| `POST /decrypt` | encrypted envelope | decrypted envelope, using the `java-server` private key |

Op parameters default to the interop happy flow (RSA-SHA256, exclusive C14N, BST key reference,
AES-256-GCM + RSA-OAEP). Override per request via query string, e.g.
`POST /sign?keyref=SubjectKeyIdentifier&sigalg=RSA_SHA512&c14n=INCLUSIVE`,
`POST /encrypt?encdata=AES256_CBC&oaep=SHA256`.

A verification "no" is a normal `200` with `valid:false` — only an unparseable body is a `400`.

## How certs/keystores wire between the container and PHP

`certs/generate.sh` issues one CA and two leaves from it, so each side trusts the other:

| File | Used by | Purpose |
|---|---|---|
| `ca.crt` | both | shared trust anchor |
| `php-client.pem` (`.key`/`.crt`) | PHP | the cert the middleware signs / decrypts with |
| `java-server.key`/`.crt` | oracle | the cert the oracle signs / decrypts with |
| `interop-recipients.p12` | oracle | the keystore the oracle loads at startup: `java-server` key (sign/decrypt) + `interop-ca` trust (verify) + `php-client` cert (encrypt recipient & SKI/IssuerSerial resolution) |
| `untrusted-*` | tests | a different CA's leaf, for negative tests |

The container mounts `certs/` at `/certs` (`docker run -v "$PWD/certs:/certs"`); the oracle reads
`interop-recipients.p12` + `ca.crt` once at startup. The PHP tests read `php-client.pem`/`ca.crt`
straight from `certs/` on the host via the `INTEROP_CERTS` env (default `certs`).

## Two-step build (fast image)

The jar is built first (Maven cache warm in `~/.m2`); the Docker image build is then just a copy and
takes seconds.

```bash
# 1. Build the oracle jar (uses local maven, or the maven docker image if maven is not on PATH)
mvn -f oracle/pom.xml -DskipTests package
#   no maven on PATH? ->
#   docker run --rm -v "$PWD:/app" -w /app -v "$HOME/.m2:/root/.m2" \
#     maven:3-eclipse-temurin-17 mvn -f oracle/pom.xml -DskipTests package

# 2. Copy-only image build (~seconds)
docker build -t java-interop-oracle .
```

## Run locally

```bash
bash certs/generate.sh
docker run -d --name oracle -p 8080:8080 -v "$PWD/certs:/certs" java-interop-oracle
curl -s http://127.0.0.1:8080/health           # -> ok

composer install
vendor/bin/phpunit --testsuite wsse
vendor/bin/phpunit --testsuite attachments

docker rm -f oracle
```

The PHPUnit tests need PHP 8.4 with `dom`, `openssl`, `intl`, `gmp`, `bcmath`. XML canonicalisation is
libxml-version sensitive; if a signature digest mismatches on an older host PHP, run PHPUnit inside a
clean PHP 8.4 image and point it at the host oracle:

```bash
docker run --rm -v "$PWD:/ji" -w /ji \
  -e INTEROP_URL=http://host.docker.internal:8080 \
  --add-host=host.docker.internal:host-gateway \
  <php84-image> vendor/bin/phpunit --testsuite wsse
```

## Running against a PR branch

A consumer middleware repo runs the interop suite against the **exact commit under review** by calling
the reusable workflow. Add this to the consumer repo's `.github/workflows/interop.yml`:

```yaml
name: interop
on: [push, pull_request]
jobs:
  wsse:
    uses: php-soap/java-interop/.github/workflows/interop.yml@main
    with:
      package: php-soap/psr18-wsse-middleware   # the consumer's composer package name
      suites: wsse                              # which testsuite(s) to run
```

How it targets the PR commit, using **one** mechanism shared with local dev:

- The harness `composer.json` declares **path repositories** to the sibling middlewares
  (`../http-wsse-middleware`, `../psr18-attachments-middleware`). Locally these point at your working
  copies; a path repository always wins over Packagist.
- In a reusable workflow a plain `actions/checkout@v4` pulls the **caller** repo — i.e. the PR commit.
  The workflow lays that checkout out at `./consumer` and **repoints the harness's path repo** for the
  package under review at it. So `vendor/` is built from the PR working copy. CI just moves the path the
  path-repo points at; local and PR runs share the same code path.
- It then runs `composer require "<package>:*@dev" --no-update` followed by a full
  `composer update --with-all-dependencies`. The harness sets `minimum-stability: dev` +
  `prefer-stable: true` so `:*@dev` resolves to the path version. `composer update` prints
  `Mirroring from ../consumer` and `composer show <package>` reports `dist: [path] ../consumer <sha>`,
  confirming the PR commit is in use.
- **Detached HEAD:** `actions/checkout` leaves PR checkouts on a detached HEAD, which stops composer
  from inferring a version for the path dependency. The workflow runs
  `git -C ../consumer checkout -B interop-pr-under-test` first, giving it a branch name so composer
  resolves a `dev-<branch>` version.

The **other** sibling middleware (the one not under review) is checked out at its released/main version
so the dependency graph still resolves.

This repo's **own** CI (`ci.yml`) runs on every push/PR and uses the sibling path repos at their
released/main checkouts — no consumer override — so changes to the harness itself are self-tested.
