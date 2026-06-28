package org.phpsoap.interop;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.wss4j.common.crypto.Crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Long-running HTTP front-end for the WSS4J interop oracle.
 *
 * <p>Wraps the same {@link Signer} / {@link Verifier} / {@link Encryptor} / {@link Decryptor} ops the
 * former CLI used, behind a tiny JDK {@link HttpServer} (no framework). The php-soap PHPUnit interop
 * tests POST SOAP envelopes here and assert the cross-stack result.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code GET  /health}  -> 200 "ok"</li>
 *   <li>{@code POST /sign}    -> WSS4J-signed envelope (text/xml)</li>
 *   <li>{@code POST /verify}  -> 200 JSON {valid:true} or {valid:false,reason:..}; 400 only on malformed input</li>
 *   <li>{@code POST /encrypt} -> WSS4J-encrypted envelope (to the php-client recipient cert)</li>
 *   <li>{@code POST /decrypt} -> decrypted envelope (with the java-server private key)</li>
 * </ul>
 *
 * <p>Op parameters (key reference, algorithms, soap version handling) are taken from the
 * {@code ScenarioConfig} defaults, overridable per request via query string (see {@link #configFrom}).
 * Defaults mirror the interop matrix happy flow: RSA-SHA256, exclusive C14N, BST key reference,
 * AES-256-GCM + RSA-OAEP for encryption.
 *
 * <p>Keystores load once at startup from a fixed directory (default {@code /certs}, mounted into the
 * container). A single PKCS12 — {@code interop-recipients.p12} — carries everything the oracle needs:
 * the java-server private key (sign / decrypt), the CA as a trusted entry (verify trust anchor), and
 * the php-client certificate (encrypt recipient + SKI/IssuerSerial resolution on verify).
 */
public final class OracleServer {

    private static final String STOREPASS = "changeit";

    private final Crypto crypto;

    private OracleServer(Crypto crypto) {
        this.crypto = crypto;
    }

    public static void main(String[] args) throws Exception {
        String certDir = System.getenv().getOrDefault("CERT_DIR", "/certs");
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));

        // One Crypto for every op: java-server key (sign/decrypt) + CA trust (verify) + php-client cert
        // (encrypt recipient). Loaded once; the engine paths are thread-safe for read-only crypto use.
        Crypto crypto = CryptoFactory.load(
                certDir + "/interop-recipients.p12",
                STOREPASS,
                "PKCS12",
                certDir + "/ca.crt");

        OracleServer server = new OracleServer(crypto);

        HttpServer http = HttpServer.create(new InetSocketAddress(port), 0);
        http.createContext("/health", server::handleHealth);
        http.createContext("/sign", server.opHandler(server::sign));
        http.createContext("/verify", server.opHandler(server::verify));
        http.createContext("/encrypt", server.opHandler(server::encrypt));
        http.createContext("/decrypt", server.opHandler(server::decrypt));
        http.createContext("/attach", server::handleAttach);
        http.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(8));
        http.start();

        System.err.println("java-interop-oracle listening on :" + port + " (certs from " + certDir + ")");
    }

    private void handleHealth(HttpExchange exchange) throws IOException {
        if (!"GET".equals(exchange.getRequestMethod())) {
            respond(exchange, 405, "text/plain", "method not allowed");
            return;
        }
        respond(exchange, 200, "text/plain", "ok");
    }

    /** A POST handler that reads the body, applies an op, and maps op outcomes to HTTP responses. */
    private HttpHandler opHandler(Op op) {
        return exchange -> {
            if (!"POST".equals(exchange.getRequestMethod())) {
                respond(exchange, 405, "text/plain", "method not allowed");
                return;
            }
            String body = readBody(exchange);
            ScenarioConfig config = configFrom(exchange.getRequestURI());
            try {
                op.apply(exchange, body, config);
            } catch (BadRequest bad) {
                respond(exchange, 400, "text/plain", bad.getMessage());
            } catch (Exception e) {
                // An unexpected server-side failure (not a verification "no", which ops handle themselves).
                respond(exchange, 500, "text/plain", rootMessage(e));
            }
        };
    }

    private void sign(HttpExchange exchange, String body, ScenarioConfig config) throws Exception {
        String signed = new Signer(crypto, config.signatureKeyAlias, STOREPASS, config).sign(parsable(body));
        respond(exchange, 200, "text/xml; charset=UTF-8", signed);
    }

    private void verify(HttpExchange exchange, String body, ScenarioConfig config) throws Exception {
        // A verification "no" is a normal 200 result with valid:false; only malformed XML is a 400.
        Verifier.Result result;
        try {
            result = new Verifier(crypto, config).verify(parsable(body));
        } catch (org.apache.wss4j.common.ext.WSSecurityException e) {
            respond(exchange, 200, "application/json", json(false, rootMessage(e)));
            return;
        }
        if (result.ok) {
            respond(exchange, 200, "application/json", json(true, null));
        } else {
            respond(exchange, 200, "application/json", json(false, String.join("; ", result.problems)));
        }
    }

    private void encrypt(HttpExchange exchange, String body, ScenarioConfig config) throws Exception {
        String encrypted = new Encryptor(crypto, config.encryptionRecipientAlias, config).encrypt(parsable(body));
        respond(exchange, 200, "text/xml; charset=UTF-8", encrypted);
    }

    private void decrypt(HttpExchange exchange, String body, ScenarioConfig config) throws Exception {
        Decryptor.Result result = new Decryptor(crypto, STOREPASS).decrypt(parsable(body));
        if (!result.encryptionProcessed) {
            respond(exchange, 400, "text/plain", "no xenc:EncryptedData was decrypted");
            return;
        }
        respond(exchange, 200, "text/xml; charset=UTF-8", result.plaintext);
    }

    /**
     * SAAJ attachment endpoint, two ops via {@code ?op=}:
     * <ul>
     *   <li>{@code op=emit} — the POST body is the raw attachment bytes; the oracle wraps them in a SwA or
     *       MTOM multipart/related (the SOAP envelope is the oracle's sample, with an xop:Include inlined for
     *       MTOM). The response body is the multipart, its media type echoed in the Content-Type header so the
     *       PHP ResponseBuilder can parse it. Used for the Java->PHP direction.</li>
     *   <li>{@code op=receive} — the POST body is a multipart produced by the PHP RequestBuilder and the
     *       request Content-Type carries its boundary. The oracle parses it with SAAJ and answers JSON
     *       {@code {count, sha256:[..], soap:".."}} so the PHP test can assert count + byte fidelity. Used for
     *       the PHP->Java direction.</li>
     * </ul>
     * Query params: {@code op} (emit|receive), {@code type} (swa|mtom), {@code protocol} (soap11|soap12),
     * {@code cid} (bare content id for emit).
     */
    private void handleAttach(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            respond(exchange, 405, "text/plain", "method not allowed");
            return;
        }
        Map<String, String> q = queryParams(exchange.getRequestURI());
        String op = q.getOrDefault("op", "receive");
        String type = q.getOrDefault("type", "swa");
        String protocol = q.getOrDefault("protocol", "soap12");

        byte[] requestBody;
        try (InputStream in = exchange.getRequestBody()) {
            requestBody = in.readAllBytes();
        }

        try {
            if ("emit".equals(op)) {
                String cid = q.getOrDefault("cid", "att1");
                byte[] soap = soapEnvelopeFor(type, cid);
                Attachments.EmitResult result = Attachments.emit(type, protocol, soap, requestBody, cid);
                exchange.getResponseHeaders().set("Content-Type", result.contentType);
                exchange.sendResponseHeaders(200, result.body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(result.body);
                }
                return;
            }

            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            if (contentType == null || contentType.isEmpty()) {
                respond(exchange, 400, "text/plain", "missing Content-Type for multipart receive");
                return;
            }
            Attachments.ReceiveResult result = Attachments.receive(requestBody, contentType, protocol);
            respond(exchange, 200, "application/json", attachJson(result));
        } catch (Exception e) {
            respond(exchange, 500, "text/plain", rootMessage(e));
        }
    }

    /** The SOAP envelope the emit op wraps: a plain Body for SwA, one carrying an xop:Include for MTOM. */
    private static byte[] soapEnvelopeFor(String type, String cid) {
        String body;
        if ("mtom".equalsIgnoreCase(type)) {
            body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    + "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\">"
                    + "<soap:Body><tns:Ping xmlns:tns=\"urn:php-soap:interop\">"
                    + "<tns:message>MTOM-INTEROP-MARKER hello from the interop harness</tns:message>"
                    + "<tns:data><xop:Include xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" href=\"cid:"
                    + cid + "\"/></tns:data>"
                    + "</tns:Ping></soap:Body></soap:Envelope>";
        } else {
            body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                    + "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\">"
                    + "<soap:Body><tns:Ping xmlns:tns=\"urn:php-soap:interop\">"
                    + "<tns:message>SWA-INTEROP-MARKER hello from the interop harness</tns:message>"
                    + "</tns:Ping></soap:Body></soap:Envelope>";
        }
        return body.getBytes(StandardCharsets.UTF_8);
    }

    private static String attachJson(Attachments.ReceiveResult result) {
        StringBuilder shas = new StringBuilder("[");
        for (int i = 0; i < result.sha256.size(); i++) {
            if (i > 0) {
                shas.append(',');
            }
            shas.append('"').append(result.sha256.get(i)).append('"');
        }
        shas.append(']');
        return "{\"count\":" + result.count
                + ",\"sha256\":" + shas
                + ",\"soap\":\"" + escapeJson(result.soapXml) + "\"}";
    }

    /**
     * Builds a per-request {@link ScenarioConfig} from query parameters, defaulting to the matrix happy
     * flow. Recognised params mirror the CLI config keys, e.g.
     * {@code ?keyref=SubjectKeyIdentifier&sigalg=RSA_SHA512&encdata=AES256_CBC&enckey=RSA_OAEP&oaep=SHA256
     * &c14n=INCLUSIVE&disableBsp=true&ts=false}.
     */
    private static ScenarioConfig configFrom(URI uri) {
        Map<String, String> q = queryParams(uri);
        ScenarioConfig config = new ScenarioConfig();
        if (q.containsKey("keyref")) {
            config.signatureKeyReference = q.get("keyref");
        }
        if (q.containsKey("sigalg")) {
            config.signatureAlgorithm = q.get("sigalg");
        }
        if (q.containsKey("sigalias")) {
            config.signatureKeyAlias = q.get("sigalias");
        }
        if (q.containsKey("enckeyref")) {
            config.encryptionKeyReference = q.get("enckeyref");
        }
        if (q.containsKey("recipient")) {
            config.encryptionRecipientAlias = q.get("recipient");
        }
        if (q.containsKey("ut")) {
            config.requireUsernameToken = Boolean.parseBoolean(q.get("ut"));
        }
        if (q.containsKey("user")) {
            config.username = q.get("user");
        }
        if (q.containsKey("pass")) {
            config.usernamePassword = q.get("pass");
        }
        if (q.containsKey("utdigest")) {
            config.usernamePasswordDigest = Boolean.parseBoolean(q.get("utdigest"));
        }
        if (q.containsKey("sig")) {
            config.requireSignature = Boolean.parseBoolean(q.get("sig"));
        }
        if (q.containsKey("c14n")) {
            config.canonicalization = q.get("c14n");
        }
        if (q.containsKey("encdata")) {
            config.dataEncryptionAlgorithm = q.get("encdata");
        }
        if (q.containsKey("enckey")) {
            config.keyEncryptionAlgorithm = q.get("enckey");
        }
        if (q.containsKey("oaep")) {
            config.oaepDigest = q.get("oaep");
        }
        if (q.containsKey("ts")) {
            config.requireTimestamp = Boolean.parseBoolean(q.get("ts"));
        }
        if (q.containsKey("disableBsp")) {
            config.disableBspEnforcement = Boolean.parseBoolean(q.get("disableBsp"));
        }
        if (q.containsKey("ttl")) {
            config.timestampTimeToLiveSeconds = Integer.parseInt(q.get("ttl"));
        }
        return config;
    }

    private static Map<String, String> queryParams(URI uri) {
        Map<String, String> out = new HashMap<>();
        String raw = uri.getRawQuery();
        if (raw == null || raw.isEmpty()) {
            return out;
        }
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                out.put(
                        java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return out;
    }

    /** Reject an obviously non-XML body early with a 400 rather than letting the parser throw a 500. */
    private static String parsable(String body) {
        String trimmed = body == null ? "" : body.trim();
        if (trimmed.isEmpty() || trimmed.charAt(0) != '<') {
            throw new BadRequest("request body is not an XML document");
        }
        return trimmed;
    }

    private static String json(boolean valid, String reason) {
        if (valid) {
            return "{\"valid\":true}";
        }
        return "{\"valid\":false,\"reason\":\"" + escapeJson(reason == null ? "" : reason) + "\"}";
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", " ");
    }

    private static String rootMessage(Throwable e) {
        Throwable cur = e;
        while (cur.getCause() != null && cur.getCause() != cur) {
            cur = cur.getCause();
        }
        String msg = cur.getMessage();
        return msg != null ? msg : cur.getClass().getSimpleName();
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        try (InputStream in = exchange.getRequestBody()) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void respond(HttpExchange exchange, int status, String contentType, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    /** A request the oracle rejects as malformed -> HTTP 400. */
    private static final class BadRequest extends RuntimeException {
        BadRequest(String message) {
            super(message);
        }
    }

    @FunctionalInterface
    private interface Op {
        void apply(HttpExchange exchange, String body, ScenarioConfig config) throws Exception;
    }
}
