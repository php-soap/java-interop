package org.phpsoap.interop;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;
import java.util.Base64;

/**
 * Hands WSS4J the session key behind an {@code #EncryptedKeySHA1} reference.
 *
 * <p>WSS4J resolves that reference through a callback and nothing else: it does not look at the
 * {@code xenc:EncryptedKey} it just decrypted in the same header, because in the deployment this was written
 * for the key came from an earlier exchange and lived in a cache. A message that carries its own key, as the
 * SymmetricBinding does, therefore needs somebody to make the connection, which is all this does: the
 * identifier is by definition the SHA-1 of a wrapped key's cipher bytes, so hashing the cipher bytes of each
 * {@code xenc:EncryptedKey} already processed finds the one it names.
 *
 * <p>Only works when the {@code xenc:EncryptedKey} precedes whatever references it in the header, which is
 * what a reader walking document order requires anyway.
 */
final class SessionKeyCallbackHandler implements CallbackHandler {

    private final CallbackHandler passwords;
    private final RequestData data;

    SessionKeyCallbackHandler(CallbackHandler passwords, RequestData data) {
        this.passwords = passwords;
        this.data = data;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            byte[] sessionKey = null;
            if (callback instanceof WSPasswordCallback pc && pc.getUsage() == WSPasswordCallback.SECRET_KEY) {
                sessionKey = sessionKeyFor(pc.getIdentifier());
                if (sessionKey != null) {
                    pc.setKey(sessionKey);
                }
            }
            if (sessionKey == null) {
                passwords.handle(new Callback[] {callback});
            }
        }
    }

    /** @return the decrypted session key whose wrapped form digests to {@code identifier}, or null. */
    private byte[] sessionKeyFor(String identifier) throws IOException {
        WSDocInfo processed = data.getWsDocInfo();
        if (identifier == null || processed == null) {
            return null;
        }

        try {
            for (WSSecurityEngineResult result : processed.getResultsByTag(WSConstants.ENCR)) {
                byte[] wrapped =
                        (byte[]) result.get(WSSecurityEngineResult.TAG_ENCRYPTED_EPHEMERAL_KEY);
                if (wrapped == null) {
                    continue;
                }
                String digest = Base64.getEncoder().encodeToString(KeyUtils.generateDigest(wrapped));
                if (digest.equals(identifier)) {
                    return (byte[]) result.get(WSSecurityEngineResult.TAG_SECRET);
                }
            }
        } catch (Exception e) {
            throw new IOException("could not digest a processed xenc:EncryptedKey", e);
        }

        return null;
    }
}
