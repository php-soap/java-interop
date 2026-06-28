package org.phpsoap.interop;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Produces a WSS4J-encrypted SOAP message whose wire shape the PHP {@code Inbound\Decrypt} block can
 * consume: an {@code xenc:EncryptedKey} (RSA key transport, wrapping a fresh symmetric session key) plus
 * an {@code xenc:EncryptedData} replacing the Body content.
 *
 * <p>The recipient certificate is named by alias in the keystore; the symmetric key is referenced by the
 * configured data-encryption algorithm. The PHP side decrypts with the matching private key, resolving the
 * recipient via the WSSE key-reference embedded by {@code setKeyIdentifierType}. We use a Subject Key
 * Identifier reference by default, which the PHP decryptor resolves against the supplied private key.
 *
 * <p>The OAEP key-transport digest/MGF is driven by {@code config.oaepDigest}: SHA-1/MGF1-SHA1 (the default,
 * the only parameterization a high-level OpenSSL decryptor accepts) or SHA-256/MGF1-SHA256.
 */
final class Encryptor {

    private final Crypto crypto;
    private final String recipientAlias;
    private final ScenarioConfig config;

    Encryptor(Crypto crypto, String recipientAlias, ScenarioConfig config) {
        this.crypto = crypto;
        this.recipientAlias = recipientAlias;
        this.config = config;
    }

    String encrypt(String xml) throws Exception {
        // The Santuario library must be initialised before WSSecEncrypt is used directly; the engine-based
        // sign/verify paths trigger this lazily, the standalone encrypt path does not.
        org.apache.xml.security.Init.init();

        Document document = Xml.parse(xml);

        WSSecHeader header = new WSSecHeader(document);
        header.insertSecurityHeader();

        String dataAlgo = dataAlgorithm(config.dataEncryptionAlgorithm);

        WSSecEncrypt encrypt = new WSSecEncrypt(header);
        encrypt.setUserInfo(recipientAlias);
        encrypt.setKeyIdentifierType(keyIdentifierType(config.encryptionKeyReference));
        encrypt.setSymmetricEncAlgorithm(dataAlgo);
        encrypt.setKeyEncAlgo(keyAlgorithm(config.keyEncryptionAlgorithm));
        encrypt.setDigestAlgorithm(oaepDigestAlgorithm(config.oaepDigest));
        encrypt.setMGFAlgorithm(oaepMgfAlgorithm(config.oaepDigest));

        encrypt.getParts().add(
                new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace(document), "Content"));

        // WSS4J 3.x asks the caller to supply the bulk session key it then wraps with the recipient key.
        // Both AES-256-GCM and AES-256-CBC use a 256-bit AES key; generate it directly so we do not depend
        // on KeyUtils' URI-to-JCE mapping (which returns no generator for the xmlenc11 GCM URI).
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey sessionKey = keyGen.generateKey();

        encrypt.build(crypto, sessionKey);

        // Emit WSS4J's native output verbatim: xenc:EncryptedData carries the XML-Enc native Id attribute.
        // The PHP decryptor resolves a xenc:DataReference target by either @Id or @wsu:Id, so no relabel
        // shim is needed for the Java->PHP direction.
        return Xml.serialize(document);
    }

    /** Maps the PHP EncKeyRef enum names to the WSS4J key-identifier constants for the recipient KeyInfo. */
    static int keyIdentifierType(String keyReference) {
        switch (keyReference) {
            case "SubjectKeyIdentifier":
                return WSConstants.SKI_KEY_IDENTIFIER;
            case "IssuerSerial":
                return WSConstants.ISSUER_SERIAL;
            case "Thumbprint":
                return WSConstants.THUMBPRINT_IDENTIFIER;
            case "BinarySecurityToken":
                return WSConstants.BST_DIRECT_REFERENCE;
            default:
                throw new IllegalArgumentException("Unknown encryption.keyReference: " + keyReference);
        }
    }

    static String dataAlgorithm(String name) {
        switch (name) {
            case "AES256_GCM":
                return WSConstants.AES_256_GCM;
            case "AES256_CBC":
                return WSConstants.AES_256;
            default:
                throw new IllegalArgumentException("Unknown encryption.data: " + name);
        }
    }

    static String oaepDigestAlgorithm(String name) {
        switch (name) {
            case "SHA1":
                return WSConstants.SHA1;
            case "SHA256":
                return WSConstants.SHA256;
            default:
                throw new IllegalArgumentException("Unknown encryption.oaepDigest: " + name);
        }
    }

    static String oaepMgfAlgorithm(String name) {
        switch (name) {
            case "SHA1":
                return WSConstants.MGF_SHA1;
            case "SHA256":
                return WSConstants.MGF_SHA256;
            default:
                throw new IllegalArgumentException("Unknown encryption.oaepDigest: " + name);
        }
    }

    static String keyAlgorithm(String name) {
        switch (name) {
            // Match the PHP enum URIs exactly: RSA_OAEP is the xmlenc11 variant, RSA_OAEP_MGF1P the older one.
            case "RSA_OAEP":
                return WSConstants.KEYTRANSPORT_RSAOAEP_XENC11;
            case "RSA_OAEP_MGF1P":
                return WSConstants.KEYTRANSPORT_RSAOAEP;
            default:
                throw new IllegalArgumentException("Unknown encryption.key: " + name);
        }
    }

    private static String soapNamespace(Document document) {
        String ns = document.getDocumentElement().getNamespaceURI();
        return ns != null ? ns : WSConstants.URI_SOAP12_ENV;
    }
}
