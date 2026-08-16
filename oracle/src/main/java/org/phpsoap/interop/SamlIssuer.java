package org.phpsoap.interop;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.bean.AuthenticationStatementBean;
import org.apache.wss4j.common.saml.bean.ConditionsBean;
import org.apache.wss4j.common.saml.bean.KeyInfoBean;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.common.saml.builder.SAML2Constants;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Stands in for the Security Token Service a Holder-of-Key deployment gets its assertions from.
 *
 * <p>The PHP middleware deliberately does not mint assertions — it imports one it was handed and signs with the
 * key that assertion vouches for. So the harness has to supply a real one, and it cannot be a committed fixture:
 * the certificates are regenerated on every run, and a Holder-of-Key assertion is bound to one specific public
 * key. An assertion frozen at commit time would name a key that no longer exists.
 *
 * <p>The assertion is signed by the CA-chained issuer, because WSS4J refuses an unsigned Holder-of-Key assertion
 * on the way in: an unsigned one is a statement anybody could have written about a key they do not hold.
 */
final class SamlIssuer {

    private static final String ISSUER = "urn:php-soap:interop:sts";

    /** Long enough that a slow suite cannot age it out, short enough to stay a plausible token lifetime. */
    private static final int VALIDITY_MINUTES = 30;

    private final Crypto crypto;

    SamlIssuer(Crypto crypto) {
        this.crypto = crypto;
    }

    /**
     * A SAML 2.0 assertion whose subject is confirmed holder-of-key against {@code holderAlias}'s certificate.
     *
     * @param holderAlias keystore alias of the key the assertion vouches for (the PHP client's)
     * @param issuerAlias keystore alias the assertion is signed with; must chain to the trusted CA
     * @param signed      when false the assertion is emitted unsigned, which is what the refusal case sends
     */
    String issue(String holderAlias, String issuerAlias, String storePassword, boolean signed) throws Exception {
        X509Certificate holder = certificateFor(holderAlias);

        // X509_CERT rather than KEY_VALUE: the whole certificate goes in the assertion's SubjectConfirmationData,
        // which is what lets a receiver match the signing certificate against the one the assertion vouches for
        // rather than merely against a bare public key.
        KeyInfoBean keyInfo = new KeyInfoBean();
        keyInfo.setCertificate(holder);
        keyInfo.setCertIdentifer(KeyInfoBean.CERT_IDENTIFIER.X509_CERT);

        SubjectBean subject = new SubjectBean(
                holder.getSubjectX500Principal().getName(),
                SAML2Constants.NAMEID_FORMAT_X509_SUBJECT_NAME,
                SAML2Constants.CONF_HOLDER_KEY);
        subject.setKeyInfo(keyInfo);

        AuthenticationStatementBean authentication = new AuthenticationStatementBean();
        authentication.setSubject(subject);
        authentication.setAuthenticationMethod("Password");

        SAMLCallback callback = new SAMLCallback();
        callback.setSamlVersion(Version.SAML_20);
        callback.setIssuer(ISSUER);
        callback.setSubject(subject);
        callback.setConditions(new ConditionsBean(VALIDITY_MINUTES));
        callback.setAuthenticationStatementData(List.of(authentication));

        SamlAssertionWrapper assertion = new SamlAssertionWrapper(callback);
        if (signed) {
            assertion.signAssertion(issuerAlias, storePassword, crypto, false);
        }

        return assertion.assertionToString();
    }

    private X509Certificate certificateFor(String alias) throws Exception {
        CryptoType type = new CryptoType(CryptoType.TYPE.ALIAS);
        type.setAlias(alias);

        X509Certificate[] certificates = crypto.getX509Certificates(type);
        if (certificates == null || certificates.length == 0) {
            throw new IllegalStateException("no certificate in the keystore for alias " + alias);
        }

        return certificates[0];
    }
}
