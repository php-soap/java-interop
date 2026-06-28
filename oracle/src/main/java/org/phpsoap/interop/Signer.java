package org.phpsoap.interop;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.w3c.dom.Document;

/**
 * Produces a WSS4J-signed SOAP message whose wire shape matches what the PHP
 * {@code Outbound\Signature} + {@code Outbound\Timestamp} + {@code Outbound\BinarySecurityToken}
 * blocks emit, so the PHP {@code Inbound\VerifySignature} can be tested against WSS4J output.
 *
 * <p>Locked-in choices to match the PHP defaults (SecurityProfile):
 * <ul>
 *   <li>Signature method: RSA-SHA256</li>
 *   <li>Digest method: SHA-256</li>
 *   <li>Canonicalisation: exclusive C14N</li>
 *   <li>Key reference: BinarySecurityToken via direct Reference (ISSUER_SERIAL etc. would differ)</li>
 *   <li>Signed parts: SOAP Body and the wsu:Timestamp</li>
 * </ul>
 */
final class Signer {

    private final Crypto crypto;
    private final String keyAlias;
    private final String keyPassword;
    private final ScenarioConfig config;

    Signer(Crypto crypto, String keyAlias, String keyPassword, ScenarioConfig config) {
        this.crypto = crypto;
        this.keyAlias = keyAlias;
        this.keyPassword = keyPassword;
        this.config = config;
    }

    String sign(String xml) throws Exception {
        Document document = Xml.parse(xml);

        WSSecHeader header = new WSSecHeader(document);
        header.setMustUnderstand(true);
        header.insertSecurityHeader();

        // UsernameToken (if required) is added before the signature so it sits in the header.
        if (config.requireUsernameToken) {
            WSSecUsernameToken usernameToken = new WSSecUsernameToken(header);
            usernameToken.setUserInfo(config.username, config.usernamePassword);
            if (config.usernamePasswordDigest) {
                usernameToken.setPasswordType(WSConstants.PASSWORD_DIGEST);
                usernameToken.addNonce();
                usernameToken.addCreated();
            } else {
                usernameToken.setPasswordType(WSConstants.PASSWORD_TEXT);
            }
            usernameToken.build();
        }

        // Timestamp first so the signature can reference it (PHP signs Body + Timestamp).
        if (config.requireTimestamp) {
            WSSecTimestamp timestamp = new WSSecTimestamp(header);
            timestamp.setTimeToLive(config.timestampTimeToLiveSeconds);
            timestamp.build();
        }

        if (config.requireSignature) {
            WSSecSignature signature = new WSSecSignature(header);
            signature.setUserInfo(keyAlias, keyPassword);
            signature.setKeyIdentifierType(keyIdentifierType(config.signatureKeyReference));
            signature.setSignatureAlgorithm(signatureAlgorithm(config.signatureAlgorithm));
            signature.setDigestAlgo(WSConstants.SHA256);
            signature.setSigCanonicalization(canonicalizationUri(config.canonicalization));

            signature.getParts().add(
                    new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace(document), "Content"));
            if (config.requireTimestamp) {
                signature.getParts().add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, "Element"));
            }

            signature.build(crypto);
        }

        return Xml.serialize(document);
    }

    /** Maps the PHP KeyRef enum names to the WSS4J key-identifier constants. */
    static int keyIdentifierType(String keyReference) {
        switch (keyReference) {
            case "BinarySecurityToken":
                return WSConstants.BST_DIRECT_REFERENCE;
            case "SubjectKeyIdentifier":
                return WSConstants.SKI_KEY_IDENTIFIER;
            case "IssuerSerial":
                return WSConstants.ISSUER_SERIAL;
            case "Thumbprint":
                return WSConstants.THUMBPRINT_IDENTIFIER;
            default:
                throw new IllegalArgumentException("Unknown signature.keyReference: " + keyReference);
        }
    }

    /**
     * Maps the canonicalization choice to the ds:SignedInfo C14N URI:
     * EXCLUSIVE -> http://www.w3.org/2001/10/xml-exc-c14n# (C14N_EXCL_OMIT_COMMENTS),
     * INCLUSIVE -> http://www.w3.org/TR/2001/REC-xml-c14n-20010315 (C14N_OMIT_COMMENTS).
     */
    static String canonicalizationUri(String canonicalization) {
        switch (canonicalization) {
            case "EXCLUSIVE":
                return WSConstants.C14N_EXCL_OMIT_COMMENTS;
            case "INCLUSIVE":
                return WSConstants.C14N_OMIT_COMMENTS;
            default:
                throw new IllegalArgumentException("Unknown signature.canonicalization: " + canonicalization);
        }
    }

    /** xmldsig-more ECDSA-SHA256 URI; WSConstants has no constant for it in this WSS4J version. */
    static final String ECDSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

    static String signatureAlgorithm(String name) {
        switch (name) {
            case "RSA_SHA256":
                return WSConstants.RSA_SHA256;
            case "RSA_SHA512":
                return WSConstants.RSA_SHA512;
            case "ECDSA_SHA256":
                return ECDSA_SHA256;
            default:
                throw new IllegalArgumentException("Unknown signature.algorithm: " + name);
        }
    }

    private static String soapNamespace(Document document) {
        String ns = document.getDocumentElement().getNamespaceURI();
        return ns != null ? ns : WSConstants.URI_SOAP12_ENV;
    }
}
