package org.phpsoap.interop;

import org.apache.wss4j.common.ext.WSPasswordCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

/**
 * Supplies the private-key password to WSS4J when it needs to unlock the recipient key for decryption,
 * and validates inbound UsernameToken passwords. A single shared secret is used for both, which is all the
 * interop harness needs: the keystore password for decryption, and the configured token password for
 * UsernameToken validation.
 */
final class CallbackHandlerStub implements CallbackHandler {

    private final String keyPassword;
    private final String usernameTokenPassword;

    CallbackHandlerStub(String keyPassword) {
        this(keyPassword, null);
    }

    CallbackHandlerStub(String keyPassword, String usernameTokenPassword) {
        this.keyPassword = keyPassword;
        this.usernameTokenPassword = usernameTokenPassword;
    }

    @Override
    public void handle(Callback[] callbacks) {
        for (Callback callback : callbacks) {
            if (callback instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callback;
                if (pc.getUsage() == WSPasswordCallback.USERNAME_TOKEN && usernameTokenPassword != null) {
                    pc.setPassword(usernameTokenPassword);
                } else {
                    pc.setPassword(keyPassword);
                }
            }
        }
    }
}
