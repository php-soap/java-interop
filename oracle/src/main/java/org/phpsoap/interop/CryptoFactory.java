package org.phpsoap.interop;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.Merlin;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Builds the WSS4J {@link Crypto} from:
 * <ul>
 *   <li>a key store (PKCS12/JKS) holding the server's own private key + cert, used to sign
 *       outbound responses, and</li>
 *   <li>a separate CA certificate (PEM) used as the trust anchor when verifying the peer.</li>
 * </ul>
 *
 * <p>The CA is loaded as its own properly-aliased trusted entry rather than relying on it being an
 * anonymous bag inside the PKCS12 — a PKCS12 built with {@code openssl ... -certfile ca.crt} leaves
 * the CA without an alias, which a Java {@code KeyStore} (hence WSS4J's Merlin trust store) ignores.
 * Both files come from {@code scripts/generate-certs.sh}; the PHP side loads {@code php-client.pem}.
 */
final class CryptoFactory {

    private CryptoFactory() {
    }

    /**
     * @param caCertPath path to the CA cert PEM, or {@code null} to fall back to the keystore as trust store.
     */
    static Crypto load(String keystorePath, String keystorePassword, String keystoreType, String caCertPath)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance(keystoreType);
        try (InputStream in = new FileInputStream(keystorePath)) {
            keyStore.load(in, keystorePassword.toCharArray());
        }

        Merlin merlin = new Merlin();
        merlin.setKeyStore(keyStore);

        if (caCertPath != null) {
            merlin.setTrustStore(trustStoreWith(caCertPath));
        } else {
            merlin.setTrustStore(keyStore);
        }
        return merlin;
    }

    private static KeyStore trustStoreWith(String caCertPath) throws Exception {
        X509Certificate ca;
        try (InputStream in = new FileInputStream(caCertPath)) {
            ca = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("interop-ca", ca);
        return trustStore;
    }
}
