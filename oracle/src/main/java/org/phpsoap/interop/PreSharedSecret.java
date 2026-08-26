package org.phpsoap.interop;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * The secret this harness pretends the two sides agreed out of band, and the name they agreed to call it.
 *
 * <p>Fixed rather than passed per request, because a shared secret travelling in a query string would be a
 * different thing from the one being tested. Both sides hard-code these, which is what "agreed out of band"
 * means when the band is a test suite.
 *
 * <p>The value type is {@code #EncryptedKeySHA1} for a reason worth knowing: WSS4J's
 * {@code CUSTOM_KEY_IDENTIFIER} emits a {@code wsse:KeyIdentifier} only for the handful of value types it
 * knows, and for a shared secret that leaves this one. Its reader is the tolerant half and accepts any value
 * type, asking a callback for the key. So a deployment whose peer is WSS4J or CXF agrees on this URI; one
 * whose peer is something else is free to agree on another, which is why the PHP side takes it as an argument
 * rather than fixing it.
 */
final class PreSharedSecret {

    /** Thirty-two bytes, which is what AES-256 takes and what a SHA-256 MAC is keyed at full strength with. */
    static final byte[] KEY = "interop-pre-shared-secret-32byte".getBytes(StandardCharsets.UTF_8);

    /** Base64, because the reference declares a base64 encoding type and the two have to agree. */
    static final String IDENTIFIER =
            Base64.getEncoder().encodeToString("interop-preshared".getBytes(StandardCharsets.UTF_8));

    static final String VALUE_TYPE =
            "http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1";

    private PreSharedSecret() {
    }
}
