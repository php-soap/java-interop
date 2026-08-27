package org.phpsoap.interop;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.message.WSSecDKEncrypt;
import org.apache.wss4j.dom.message.WSSecDKSign;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecEncryptedKey;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.w3c.dom.Document;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.List;

/**
 * The WS-SecurityPolicy SymmetricBinding: one session key, wrapped once in an {@code xenc:EncryptedKey},
 * keying the signature (as an HMAC) and the encryption both. Unlike the asymmetric flow, where signing and
 * encryption are independent blocks that happen to sit in the same header, here they are two uses of one key,
 * so one class emits both.
 *
 * <p>Two things about the wire shape are the reason this exists. First, the {@code xenc:ReferenceList} is a
 * SIBLING of the {@code xenc:EncryptedKey} rather than a child of it, which is what lets a signature cover the
 * key element for token protection without the encryption block writing into that same element afterwards.
 * The price is a {@code ds:KeyInfo} on every {@code xenc:EncryptedData}, since a detached reference list no
 * longer says which key opens what. Second, the key is named by {@code #EncryptedKeySHA1}, the digest of the
 * key's CIPHER bytes, which is the one identifier both peers can compute: the session key itself is known
 * only to the sender until the recipient unwraps it.
 *
 * <p>Header layout falls out of WSS4J prepending each block it builds, and the resulting document order is
 * load-bearing rather than cosmetic. A reader walking the header meets the {@code xenc:EncryptedKey} first, so
 * it holds the session key by the time the {@code xenc:ReferenceList} asks it to decrypt, and the Body is
 * plaintext again by the time the {@code ds:Signature} asks it to verify.
 *
 * <p>With {@code derivedkeys=true} each block gets its own {@code wsc:DerivedKeyToken} off that single
 * {@code xenc:EncryptedKey} instead, P_SHA1 over a per-token nonce, which is what {@code sp:RequireDerivedKeys}
 * asks for, and what a live peer has been seen sending.
 */
final class SymmetricBinding {

    private final Crypto crypto;
    private final ScenarioConfig config;
    private final String keyPassword;

    SymmetricBinding(Crypto crypto, ScenarioConfig config, String keyPassword) {
        this.crypto = crypto;
        this.config = config;
        this.keyPassword = keyPassword;
    }

    /**
     * @param signedParts what the signature covers, decided by the caller so the asymmetric and symmetric
     *                    flows cannot drift on it
     */
    void apply(Document document, WSSecHeader header, List<WSEncryptionPart> signedParts) throws Exception {
        // Santuario must be initialised before the encryption classes are used directly; the engine-based
        // paths trigger it lazily, this one does not.
        org.apache.xml.security.Init.init();

        if (config.preSharedKey) {
            // Nothing to convey: both sides hold the key, so no xenc:EncryptedKey is written and the blocks
            // name the key by the identifier the two agreed on.
            applyPreShared(document, header, signedParts);

            return;
        }

        SecretKey sessionKey = sessionKey();
        WSSecEncryptedKey encryptedKey = encryptedKey(header);
        encryptedKey.prepare(crypto, sessionKey);

        if (config.requireDerivedKeys) {
            deriveAndApply(document, header, signedParts, encryptedKey, sessionKey);
        } else {
            applyDirectly(document, header, signedParts, encryptedKey, sessionKey);
        }

        // Last, so it lands in front of everything that needs it.
        encryptedKey.prependToHeader();
    }

    /**
     * Sign and encrypt with a key the peer already holds, naming it by the identifier the peer minted. No
     * xenc:EncryptedKey is written: the key travelled with the request, so the answer only points at it.
     *
     * @param encryptedKeySha1 the identifier the request's own wrapped key digests to, which is the only name
     *        both sides can compute once the key element itself is not in this message
     */
    void applyWithEstablishedKey(
            Document document,
            WSSecHeader header,
            List<WSEncryptionPart> signedParts,
            SecretKey sessionKey,
            String encryptedKeySha1) throws Exception {

        org.apache.xml.security.Init.init();

        if (config.requireDerivedKeys) {
            deriveFromEstablishedKey(document, header, signedParts, sessionKey, encryptedKeySha1);

            return;
        }

        WSSecSignature signature = new WSSecSignature(header);
        signature.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        signature.setEncrKeySha1value(encryptedKeySha1);
        signature.setSecretKey(sessionKey.getEncoded());
        signature.setSignatureAlgorithm(macAlgorithm());
        signature.setDigestAlgo(WSConstants.SHA256);
        signature.setSigCanonicalization(Signer.canonicalizationUri(config.canonicalization));
        signature.getParts().addAll(signedParts);
        signature.build(crypto);

        endorse(header, signature);

        WSSecEncrypt encrypt = new WSSecEncrypt(header);
        encrypt.setEncryptSymmKey(false);
        encrypt.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        encrypt.setCustomReferenceValue(encryptedKeySha1);
        encrypt.setSymmetricEncAlgorithm(Encryptor.dataAlgorithm(config.dataEncryptionAlgorithm));
        encrypt.getParts().add(bodyContent(document));
        encrypt.build(crypto, sessionKey);
    }

    /**
     * Add an endorsing supporting token over a signature already built: a second signature keyed by this
     * server's certificate covering the primary one, which is what sp:EndorsingSupportingTokens asks for.
     *
     * <p>Under {@link ScenarioConfig#protectEndorsingToken} it also covers its own wsse:BinarySecurityToken,
     * the way CXF's AbstractBindingBuilder does when the binding asks for token protection. That variant is
     * the one worth emitting: a receiver may recognise an endorsement by it covering a signature, and one that
     * additionally requires it to cover nothing else refuses this message.
     *
     * <p>Runs before the encryption block so the endorsement covers the signature as the signature stands, and
     * so sign-then-encrypt still describes the message.
     */
    private void endorse(WSSecHeader header, WSSecSignature endorsed) throws Exception {
        if (!config.endorseSignature) {
            return;
        }

        WSSecSignature endorsement = new WSSecSignature(header);
        endorsement.setUserInfo(config.signatureKeyAlias, keyPassword);
        endorsement.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        endorsement.setSignatureAlgorithm(WSConstants.RSA_SHA256);
        endorsement.setDigestAlgo(WSConstants.SHA256);
        endorsement.setSigCanonicalization(Signer.canonicalizationUri(config.canonicalization));

        WSEncryptionPart primary = new WSEncryptionPart(endorsed.getId());
        primary.setElement(endorsed.getSignatureElement());
        endorsement.getParts().add(primary);

        if (config.protectEndorsingToken) {
            // The token has to reach its final position before it is digested: prepare() leaves it detached,
            // and moving it afterwards changes the namespaces it inherits and so the canonical form the digest
            // was taken over. build() gets away with digesting first because it prepends the same element it
            // just created; here the element is also a signing target.
            endorsement.prepare(crypto);
            endorsement.prependBSTElementToHeader();

            WSEncryptionPart token = new WSEncryptionPart(endorsement.getBSTTokenId());
            token.setElement(endorsement.getBinarySecurityTokenElement());
            endorsement.getParts().add(token);
            endorsement.computeSignature(endorsement.addReferencesToSign(endorsement.getParts()), false, null);

            return;
        }

        endorsement.build(crypto);
    }

    /**
     * Derive one key per block from a key the peer already holds, each announced by its own wsc:DerivedKeyToken
     * that names the shared key by its EncryptedKeySHA1 rather than by an element this message does not carry.
     */
    private void deriveFromEstablishedKey(
            Document document,
            WSSecHeader header,
            List<WSEncryptionPart> signedParts,
            SecretKey sessionKey,
            String encryptedKeySha1) throws Exception {

        WSSecDKSign signature = new WSSecDKSign(header);
        signature.setWscVersion(config.wsSecureConversationVersion);
        signature.setTokenIdentifier(encryptedKeySha1);
        signature.setCustomValueType(WSConstants.SOAPMESSAGE_NS11 + "#EncryptedKeySHA1");
        signature.setSignatureAlgorithm(macAlgorithm());
        signature.setDigestAlgorithm(WSConstants.SHA256);
        signature.setSigCanonicalization(Signer.canonicalizationUri(config.canonicalization));
        signature.getParts().addAll(signedParts);
        signature.build(sessionKey.getEncoded());

        WSSecDKEncrypt encrypt = new WSSecDKEncrypt(header);
        encrypt.setWscVersion(config.wsSecureConversationVersion);
        encrypt.setTokenIdentifier(encryptedKeySha1);
        encrypt.setCustomValueType(WSConstants.SOAPMESSAGE_NS11 + "#EncryptedKeySHA1");
        encrypt.setSymmetricEncAlgorithm(Encryptor.dataAlgorithm(config.dataEncryptionAlgorithm));
        encrypt.getParts().add(bodyContent(document));
        encrypt.build(sessionKey.getEncoded());
    }

    /**
     * Sign and encrypt with a secret both sides already hold, named by the identifier they agreed on. No
     * xenc:EncryptedKey and nothing derived: this is the {@code ENC_SYM_ENC_KEY=false} shape.
     */
    private void applyPreShared(Document document, WSSecHeader header, List<WSEncryptionPart> signedParts)
            throws Exception {

        SecretKey secret = new javax.crypto.spec.SecretKeySpec(PreSharedSecret.KEY, "AES");

        WSSecSignature signature = new WSSecSignature(header);
        signature.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
        signature.setCustomTokenValueType(PreSharedSecret.VALUE_TYPE);
        signature.setCustomTokenId(PreSharedSecret.IDENTIFIER);
        signature.setSecretKey(PreSharedSecret.KEY);
        signature.setSignatureAlgorithm(macAlgorithm());
        signature.setDigestAlgo(WSConstants.SHA256);
        signature.setSigCanonicalization(Signer.canonicalizationUri(config.canonicalization));
        signature.getParts().addAll(signedParts);
        signature.build(crypto);

        WSSecEncrypt encrypt = new WSSecEncrypt(header);
        encrypt.setEncryptSymmKey(false);
        encrypt.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
        encrypt.setCustomReferenceValue(PreSharedSecret.VALUE_TYPE);
        encrypt.setEncKeyId(PreSharedSecret.IDENTIFIER);
        encrypt.setSymmetricEncAlgorithm(Encryptor.dataAlgorithm(config.dataEncryptionAlgorithm));
        encrypt.getParts().add(bodyContent(document));
        encrypt.build(crypto, secret);
    }

    /** The SOAP Body content, as the part list every symmetric flow here covers. */
    static WSEncryptionPart bodyContentPart(Document document) {
        return bodyContent(document);
    }

    /** Sign and encrypt with the session key itself, naming it by the digest of its cipher bytes. */
    private void applyDirectly(
            Document document,
            WSSecHeader header,
            List<WSEncryptionPart> signedParts,
            WSSecEncryptedKey encryptedKey,
            SecretKey sessionKey) throws Exception {

        WSSecSignature signature = new WSSecSignature(header);
        signature.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        signature.setEncrKeySha1value(encryptedKey.getEncryptedKeySHA1());
        signature.setSecretKey(sessionKey.getEncoded());
        signature.setSignatureAlgorithm(macAlgorithm());
        signature.setDigestAlgo(WSConstants.SHA256);
        signature.setSigCanonicalization(Signer.canonicalizationUri(config.canonicalization));
        signature.getParts().addAll(signedParts);
        signature.build(crypto);

        WSSecEncrypt encrypt = new WSSecEncrypt(header);
        // The key is already on the wire in the block above, so this one references it rather than wrapping a
        // second copy. That is also what makes WSS4J emit the reference list detached instead of nested.
        encrypt.setEncryptSymmKey(false);
        encrypt.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
        // Without this WSS4J would name the session key by its own digest rather than by the digest of the
        // cipher bytes, which is an identifier no recipient can reproduce.
        encrypt.setCustomReferenceValue(encryptedKey.getEncryptedKeySHA1());
        encrypt.setSymmetricEncAlgorithm(Encryptor.dataAlgorithm(config.dataEncryptionAlgorithm));
        encrypt.getParts().add(bodyContent(document));
        encrypt.build(crypto, sessionKey);
    }

    /** Derive one key per block from the session key, each announced by its own wsc:DerivedKeyToken. */
    private void deriveAndApply(
            Document document,
            WSSecHeader header,
            List<WSEncryptionPart> signedParts,
            WSSecEncryptedKey encryptedKey,
            SecretKey sessionKey) throws Exception {

        WSSecDKSign signature = new WSSecDKSign(header);
        signature.setWscVersion(config.wsSecureConversationVersion);
        signature.setTokenIdentifier(encryptedKey.getId());
        signature.setCustomValueType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
        signature.setSignatureAlgorithm(macAlgorithm());
        signature.setDigestAlgorithm(WSConstants.SHA256);
        signature.setSigCanonicalization(Signer.canonicalizationUri(config.canonicalization));
        signature.getParts().addAll(signedParts);
        signature.build(sessionKey.getEncoded());

        WSSecDKEncrypt encrypt = new WSSecDKEncrypt(header);
        encrypt.setWscVersion(config.wsSecureConversationVersion);
        encrypt.setTokenIdentifier(encryptedKey.getId());
        encrypt.setCustomValueType(WSConstants.WSS_ENC_KEY_VALUE_TYPE);
        encrypt.setSymmetricEncAlgorithm(Encryptor.dataAlgorithm(config.dataEncryptionAlgorithm));
        encrypt.getParts().add(bodyContent(document));
        encrypt.build(sessionKey.getEncoded());
    }

    /**
     * The signature here is keyed by the session key, so its algorithm has to be a keyed MAC. Refused rather
     * than quietly substituted: an RSA name reaching this path means the caller believes a certificate is
     * signing, and a message that says HMAC while the sender thought otherwise is the confusion this whole
     * feature has to avoid.
     */
    private String macAlgorithm() {
        if (!config.signatureAlgorithm.startsWith("HMAC_")) {
            throw new IllegalArgumentException(
                    "a symmetric binding needs an HMAC signature.algorithm, got: " + config.signatureAlgorithm);
        }

        return Signer.signatureAlgorithm(config.signatureAlgorithm);
    }

    private WSSecEncryptedKey encryptedKey(WSSecHeader header) {
        WSSecEncryptedKey encryptedKey = new WSSecEncryptedKey(header);
        encryptedKey.setUserInfo(config.encryptionRecipientAlias);
        encryptedKey.setKeyIdentifierType(Encryptor.keyIdentifierType(config.encryptionKeyReference));
        encryptedKey.setKeyEncAlgo(Encryptor.keyAlgorithm(config.keyEncryptionAlgorithm));
        encryptedKey.setDigestAlgorithm(Encryptor.oaepDigestAlgorithm(config.oaepDigest));
        encryptedKey.setMGFAlgorithm(Encryptor.oaepMgfAlgorithm(config.oaepDigest));

        return encryptedKey;
    }

    /**
     * Both AES-256-GCM and AES-256-CBC take a 256-bit AES key, and a keyed MAC accepts a key of any length, so
     * one generator serves every algorithm combination the scenario offers.
     */
    private static SecretKey sessionKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);

        return generator.generateKey();
    }

    private static WSEncryptionPart bodyContent(Document document) {
        String namespace = document.getDocumentElement().getNamespaceURI();

        return new WSEncryptionPart(
                WSConstants.ELEM_BODY,
                namespace != null ? namespace : WSConstants.URI_SOAP12_ENV,
                "Content");
    }
}
