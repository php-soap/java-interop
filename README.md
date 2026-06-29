# php-soap / java-interop

Cross-stack SOAP interop tests. PHPUnit tests drive the php-soap middlewares and assert they
interoperate, over HTTP, with a Dockerised Apache WSS4J reference implementation (the "oracle").

This is a test harness, not a published library. Do not `composer require` it as a dependency; run it
through its own test suite (see [Run locally](#run-locally)) or the reusable CI workflow.

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

# Want to help out? 💚

- [Become a Sponsor](https://github.com/php-soap/.github/blob/main/HELPING_OUT.md#sponsor)
- [Let us do your implementation](https://github.com/php-soap/.github/blob/main/HELPING_OUT.md#let-us-do-your-implementation)
- [Contribute](https://github.com/php-soap/.github/blob/main/HELPING_OUT.md#contribute)
- [Help maintain these packages](https://github.com/php-soap/.github/blob/main/HELPING_OUT.md#maintain)

Want more information about the future of this project? Check out this list of the [next big projects](https://github.com/php-soap/.github/blob/main/PROJECTS.md) we'll be working on.

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
composer.json           dev tooling (declares no repositories; the source is injected per context)
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
| `GET /health` | (none) | `200 ok` |
| `POST /sign` | SOAP envelope | WSS4J-signed envelope (`text/xml`) |
| `POST /verify` | signed envelope | `200 {"valid":true}` or `200 {"valid":false,"reason":"..."}`; `400` only on malformed XML |
| `POST /encrypt` | envelope | WSS4J-encrypted envelope, recipient = `php-client` cert |
| `POST /decrypt` | encrypted envelope | decrypted envelope, using the `java-server` private key |
| `POST /attach?op=emit` | raw attachment bytes | SwA/MTOM multipart (media type in the `Content-Type` header) for the PHP ResponseBuilder |
| `POST /attach?op=receive` | PHP multipart body | `200 {"count":N,"sha256":[..],"soap":".."}` parsed by SAAJ |

Op parameters default to the interop happy flow (RSA-SHA256, exclusive C14N, BST key reference,
AES-256-GCM + RSA-OAEP). Override per request via query string, e.g.
`POST /sign?keyref=SubjectKeyIdentifier&sigalg=RSA_SHA512&c14n=INCLUSIVE`,
`POST /encrypt?encdata=AES256_CBC&oaep=SHA256&enckeyref=IssuerSerial`.

Recognised query params:
- `/sign`: `keyref`, `sigalg` (`RSA_SHA256|RSA_SHA512|ECDSA_SHA256`), `sigalias` (`java-server`|`ec-client`), `c14n`, `disableBsp`, `ttl`.
- `/verify`: `sigalg`, `disableBsp`, `ttl`; `sig`/`ts`/`ut` (require-flags) + `user`/`pass`/`utdigest` for UsernameToken validation.
- `/encrypt`: `encdata` (`AES256_GCM|AES256_CBC`), `oaep` (`SHA1|SHA256`), `enckeyref` (`SubjectKeyIdentifier|IssuerSerial`), `recipient`.
- `/attach`: `op` (`emit|receive`), `type` (`swa|mtom`), `protocol` (`soap11|soap12`), `cid`.

A verification "no" is a normal `200` with `valid:false`. Only an unparseable body returns `400`.

## How certs/keystores wire between the container and PHP

`certs/generate.sh` issues one CA and two leaves from it, so each side trusts the other:

| File | Used by | Purpose |
|---|---|---|
| `ca.crt` | both | shared trust anchor |
| `php-client.pem` (`.key`/`.crt`) | PHP | the cert the middleware signs / decrypts with |
| `java-server.key`/`.crt` | oracle | the cert the oracle signs / decrypts with |
| `ec-client.pem` (`.key`/`.crt`) | both | EC P-256 leaf for the ECDSA-SHA256 axis (PHP signs with it; oracle holds the key under the `ec-client` alias) |
| `interop-recipients.p12` | oracle | the keystore the oracle loads at startup: `java-server` key (sign/decrypt) + `interop-ca` trust (verify) + `php-client` cert (encrypt recipient & SKI/IssuerSerial resolution) + `ec-client` key (ECDSA sign/verify) |
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
#     maven:3-eclipse-temurin-21 mvn -f oracle/pom.xml -DskipTests package

# 2. Copy-only image build (~seconds)
docker build -t java-interop-oracle .
```

## Run locally

One command, Docker-only:

```bash
make interop                 # full suite (wsse + attachments)
make interop SUITE=wsse      # one testsuite: wsse | attachments
```

The only prerequisite is Docker: no host PHP, Java, or Maven. `make interop` builds the oracle jar
(via the maven docker image, `~/.m2` cached), builds the two images, (re)generates the certs, starts the
oracle and waits until it is healthy, runs PHPUnit in the PHP container, and always tears everything
down at the end (even when a test fails).

Running everything in containers also avoids host-libxml differences: XML canonicalisation is
libxml-version sensitive, and the PHP runner image is a recent `php:8.5-cli` (past the older host
8.4.13 libxml C14N quirk).

### Compose model

`docker-compose.yml` defines two services on the default compose network:

- `oracle`: the WSS4J reference server (built from `Dockerfile`, certs mounted at `/certs`, a
  `/health` healthcheck).
- `php`: the PHPUnit runner (built from `tests/php.Dockerfile`). It mounts the parent `php-soap`
  directory at `/work` so the sibling working copies (`../http-wsse-middleware`,
  `../psr18-attachments-middleware`) resolve, and reaches the oracle by service name
  (`INTEROP_URL=http://oracle:8080`) over the compose network, so the tests need no
  `host.docker.internal` and no published port.

The committed `composer.json` declares no repositories. `make test` / `make interop` copy it to a
gitignored `composer.run.json` and inject path repos to the two sibling working copies there, so the
committed file is never dirtied. Those siblings are expected to be checked out next to this repo (on
the branches that carry the code the tests exercise).

### Individual targets

```bash
make help     # list targets
make jar      # build oracle/target/java-interop-oracle.jar (maven docker image, ~/.m2 cached)
make certs    # (re)generate the shared cert material
make images   # build the oracle + php docker images
make up       # start the oracle and wait until healthy
make test [SUITE=wsse|attachments]   # run PHPUnit in the php container
make down     # stop everything and remove the compose volumes
make clean    # remove the built jar and compose volumes
```

## Running against a PR branch

A consumer middleware repo runs the interop suite against the exact commit under review by calling
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

It runs on PHP 8.4 and 8.5 by default; pass `php-versions` (a JSON array) to change that.

How it targets the code under test, with nothing hardcoded:

- The harness `composer.json` declares no repositories; the workflow supplies the source at runtime.
- `actions/checkout` pulls the caller. For a pull request it resolves the originating repository and
  ref, so a fork's PR is checked out from the fork. That checkout is the package source, whatever ref
  triggered the run: a branch, a tag, or a pull request.
- The workflow puts that checkout on a fixed local branch and adds it as a path repo, so composer always
  presents it as `dev-interop-ref` and resolves the exact checked-out code. The fixed name is what keeps
  it ref-agnostic: a tag like `0.10.0` would otherwise normalise to `0.10.0.x-dev` and miss a dev
  constraint. No `@dev`, and no branch, tag, or repository baked into the workflow.

The source is injected per context: local `make` adds path repos to the `../` siblings; `interop.yml`
adds a path repo to the PR checkout; `ci.yml` declares nothing and resolves from Packagist, so it goes
green once the middleware code these tests exercise is released to its main branch.
