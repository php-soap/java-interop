package org.phpsoap.interop;

import jakarta.xml.soap.AttachmentPart;
import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.MimeHeaders;
import jakarta.xml.soap.SOAPConstants;
import jakarta.xml.soap.SOAPMessage;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecEncryptedKey;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.w3c.dom.Document;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * WS-Security over SOAP attachments, per the WSS SwA Profile 1.1, as the oracle side of the interop matrix.
 *
 * <p>The existing {@link Signer} and {@link Encryptor} take XML alone and cannot serve this: an attachment's
 * bytes are not in the document, so WSS4J reaches them through
 * {@link AttachmentCallbackHandler} instead. Both operations name {@code cid:Attachments} as a part, which is
 * WSS4J's own way of saying "every attachment on this message" and is what a
 * {@code sp:Attachments} policy assertion turns into.
 *
 * <p>Two directions, one class:
 * <ul>
 *   <li>{@link #secure} takes a plain multipart from PHP and returns a signed and/or encrypted one, so the PHP
 *       verifier and decryptor can be tested against WSS4J output.</li>
 *   <li>{@link #check} takes a secured multipart from PHP and reports what WSS4J made of it, including the
 *       SHA-256 of each attachment <em>after</em> processing, which is what proves a decryption actually
 *       recovered the original bytes rather than merely not failing.</li>
 * </ul>
 */
final class AttachmentSecurity {

    private static final String KEYSTORE_PASSWORD = "changeit";

    /** WSS4J's part name meaning "every attachment on this message". */
    private static final String ALL_ATTACHMENTS = "cid:Attachments";

    private final Crypto crypto;
    private final ScenarioConfig config;

    AttachmentSecurity(Crypto crypto, ScenarioConfig config) {
        this.crypto = crypto;
        this.config = config;
    }

    /** What WSS4J made of a secured multipart, plus the attachment digests before and after processing. */
    static final class CheckResult {
        final boolean ok;
        final List<String> problems;
        final List<String> attachmentSha256;
        final List<String> rawAttachmentSha256;
        final List<String> attachmentHeaderBlocks;
        final boolean sawSignature;
        final boolean sawEncryption;

        /**
         * The soap:Body as it stands once the engine is done with it.
         *
         * Reported because "the header processed" is not the same claim as "the content came back". Where the
         * body itself was encrypted, nothing in the attachment digests says whether it was opened, and an
         * engine that quietly did nothing also does not fail.
         */
        final String body;

        CheckResult(
                boolean ok,
                List<String> problems,
                List<String> attachmentSha256,
                List<String> rawAttachmentSha256,
                List<String> attachmentHeaderBlocks,
                boolean sawSignature,
                boolean sawEncryption,
                String body) {
            this.ok = ok;
            this.problems = problems;
            this.attachmentSha256 = attachmentSha256;
            this.rawAttachmentSha256 = rawAttachmentSha256;
            this.attachmentHeaderBlocks = attachmentHeaderBlocks;
            this.sawSignature = sawSignature;
            this.sawEncryption = sawEncryption;
            this.body = body;
        }
    }

    /**
     * Runs the WSS4J engine over a multipart message, letting it reach the attachments through the callback
     * handler, then reports whether the required protections were present and what the attachments hash to
     * afterwards.
     *
     * <p>The post-processing digest is the whole point of returning it. A decryption that silently did nothing
     * also "does not fail", so only comparing the recovered bytes against the original proves the round trip.
     * The digest taken before processing answers the other half: it says what actually crossed the wire, which
     * is how a caller tells an encrypted part from one that travelled in the clear.
     */
    CheckResult check(byte[] body, String contentType, String protocol) throws Exception {
        SOAPMessage message = parse(body, contentType, protocol);
        Document document = message.getSOAPPart().getEnvelope().getOwnerDocument();

        List<Attachment> inbound = attachmentsOf(message);

        // Taken from the MIME parts rather than from the WSS4J attachments, whose streams the engine consumes.
        List<String> rawDigests = new ArrayList<>();
        Iterator<?> rawParts = message.getAttachments();
        while (rawParts.hasNext()) {
            rawDigests.add(sha256(((AttachmentPart) rawParts.next()).getRawContentBytes()));
        }

        // What WSS4J canonicalizes the inbound headers to, reported whatever the outcome. A complete
        // coverage disagreement surfaces as nothing but a digest mismatch, so the block itself is the only
        // diagnosable thing the far side can compare against.
        List<String> headerBlocks = new ArrayList<>();
        for (Attachment attachment : inbound) {
            java.io.ByteArrayOutputStream canonical = new java.io.ByteArrayOutputStream();
            AttachmentUtils.canonizeMimeHeaders(canonical, attachment.getHeaders());
            headerBlocks.add(canonical.toString(StandardCharsets.UTF_8));
        }

        AttachmentCallbackHandler attachmentHandler = new AttachmentCallbackHandler(inbound);

        RequestData data = new RequestData();
        data.setSigVerCrypto(crypto);
        data.setDecCrypto(crypto);
        // Wrapped for the same reason the verifier and the decryptor wrap theirs: an #EncryptedKeySHA1
        // reference is resolved through a callback and nowhere else, so an attachment encrypted under a key a
        // signature also uses cannot be opened without one.
        data.setCallbackHandler(new SessionKeyCallbackHandler(
                new CallbackHandlerStub(KEYSTORE_PASSWORD, config.usernamePassword), data));
        data.setAttachmentCallbackHandler(attachmentHandler);
        data.setWssConfig(WSSConfig.getNewInstance());
        data.setDisableBSPEnforcement(config.disableBspEnforcement);
        data.setTimeStampTTL(config.timestampTimeToLiveSeconds);
        data.setTimeStampFutureTTL(config.timestampFutureTimeToLiveSeconds);

        WSHandlerResult handlerResult;
        try {
            handlerResult = new WSSecurityEngine().processSecurityHeader(document, data);
        } catch (Exception refused) {
            // A refusal is a result, not a server error, and this is the one case the header blocks are
            // worth reporting: a complete coverage that disagrees surfaces as nothing but an invalid
            // signature, so the far side needs the block this stack canonicalized to compare against.
            return new CheckResult(
                    false,
                    List.of(rootMessage(refused)),
                    List.of(),
                    rawDigests,
                    headerBlocks,
                    false,
                    false,
                    "");
        }

        // Per action, the attachments it actually covered. WSS4J marks a data reference as an attachment and
        // records the cid: URI it named, so this distinguishes "the message carried a signature" from "the
        // signature covered this attachment", which a body-only signature would otherwise pass for.
        Set<String> signed = coveredAttachments(handlerResult, WSConstants.SIGN);
        Set<String> encrypted = coveredAttachments(handlerResult, WSConstants.ENCR);

        Set<String> ids = new HashSet<>();
        for (Attachment attachment : inbound) {
            ids.add(attachment.getId());
        }

        boolean sawSignature = !signed.isEmpty() && signed.containsAll(ids);
        boolean sawEncryption = !encrypted.isEmpty() && encrypted.containsAll(ids);

        List<String> problems = new ArrayList<>();
        if (config.signAttachments && !sawSignature) {
            problems.add("no signature over the attachments");
        }
        if (config.encryptAttachments && !sawEncryption) {
            problems.add("no encryption of the attachments");
        }

        // Prefer what WSS4J handed back: after decryption those are the recovered plaintext streams. With no
        // transformation to report (a signature leaves the bytes alone) the inbound parts are the answer.
        List<Attachment> reportable = attachmentHandler.results();
        if (reportable.isEmpty()) {
            reportable = inbound;
        }
        if (reportable.isEmpty()) {
            problems.add("the message carried no attachment");
        }

        List<String> digests = new ArrayList<>();
        for (Attachment attachment : reportable) {
            digests.add(sha256(attachment.getSourceStream().readAllBytes()));
        }

        return new CheckResult(
                problems.isEmpty(),
                problems,
                digests,
                rawDigests,
                headerBlocks,
                sawSignature,
                sawEncryption,
                Xml.serialize(document));
    }

    /** The bare Content-IDs the given action covered, taken from the data references WSS4J reports. */
    private static String rootMessage(Throwable e) {
        Throwable cur = e;
        while (cur.getCause() != null && cur.getCause() != cur) {
            cur = cur.getCause();
        }

        return cur.getMessage() != null ? cur.getMessage() : cur.getClass().getSimpleName();
    }

    private static Set<String> coveredAttachments(WSHandlerResult handlerResult, int wanted) {
        Set<String> covered = new HashSet<>();
        for (WSSecurityEngineResult result : handlerResult.getResults()) {
            Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            if (action == null || action != wanted) {
                continue;
            }

            Object refs = result.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
            if (!(refs instanceof List<?>)) {
                continue;
            }

            for (Object ref : (List<?>) refs) {
                if (ref instanceof WSDataRef dataRef && dataRef.isAttachment()) {
                    covered.add(bare(dataRef.getWsuId()));
                }
            }
        }

        return covered;
    }

    /**
     * Signs and/or encrypts the attachments of a plain multipart and returns the secured multipart.
     *
     * <p>Sign before encrypt, matching what the PHP outbound list does and what the far side needs: the
     * signature covers the plaintext, and the inbound peer must decrypt before verifying.
     */
    Attachments.EmitResult secure(byte[] body, String contentType, String protocol) throws Exception {
        org.apache.xml.security.Init.init();
        // Registers the SwA transform providers with the JCE. Without it the signature factory reports the
        // Attachment-Content-Signature-Transform as "algorithm and DOM mechanism not available": the engine
        // paths do this for themselves, the standalone message-builder path does not.
        WSSConfig.init();

        SOAPMessage message = parse(body, contentType, protocol);
        Document document = message.getSOAPPart().getEnvelope().getOwnerDocument();

        List<Attachment> parts = attachmentsOf(message);
        // storeBytesInAttachment mints the only part such a message needs, so it is the one scenario where
        // arriving without an attachment is the normal case rather than a caller mistake.
        if (parts.isEmpty() && !config.storeBytesInAttachment) {
            throw new IllegalArgumentException("The request carried no attachment to secure.");
        }

        WSSecHeader header = new WSSecHeader(document);
        header.setMustUnderstand(true);
        header.insertSecurityHeader();

        if (config.requireTimestamp) {
            WSSecTimestamp timestamp = new WSSecTimestamp(header);
            timestamp.setTimeToLive(config.timestampTimeToLiveSeconds);
            timestamp.build();
        }

        if (config.symmetricBinding) {
            return emit(document, secureUnderOneKey(document, header, parts), protocol);
        }

        AttachmentCallbackHandler signHandler = new AttachmentCallbackHandler(parts);
        if (config.signAttachments) {
            WSSecSignature signature = new WSSecSignature(header);
            signature.setUserInfo(config.signatureKeyAlias, KEYSTORE_PASSWORD);
            signature.setKeyIdentifierType(Signer.keyIdentifierType(config.signatureKeyReference));
            signature.setSignatureAlgorithm(Signer.signatureAlgorithm(config.signatureAlgorithm));
            signature.setDigestAlgo(WSConstants.SHA256);
            signature.setSigCanonicalization(Signer.canonicalizationUri(config.canonicalization));
            signature.setAttachmentCallbackHandler(signHandler);
            // Moves the wsse:BinarySecurityToken bytes into a part of their own, leaving an xop:Include in
            // the token. WSS4J always expands that again on the way in when the token is signed.
            signature.setStoreBytesInAttachment(config.storeBytesInAttachment);

            signature.getParts().add(
                    new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace(document), "Content"));
            if (config.requireTimestamp) {
                signature.getParts().add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, "Element"));
            }
            if (config.signAttachments && !parts.isEmpty()) {
                signature.getParts().add(
                        new WSEncryptionPart(ALL_ATTACHMENTS, config.attachmentSignatureCoverage));
            }

            signature.build(crypto);
        }

        // The attachments as they stand after signing: unchanged, since a signature only reads them.
        List<Attachment> current = signHandler.results().isEmpty() ? parts : signHandler.results();

        AttachmentCallbackHandler encryptHandler = new AttachmentCallbackHandler(current);
        if (config.encryptAttachments || config.storeBytesInAttachment) {
            WSSecEncrypt encrypt = new WSSecEncrypt(header);
            encrypt.setUserInfo(config.encryptionRecipientAlias);
            encrypt.setKeyIdentifierType(Encryptor.keyIdentifierType(config.encryptionKeyReference));
            encrypt.setSymmetricEncAlgorithm(Encryptor.dataAlgorithm(config.dataEncryptionAlgorithm));
            encrypt.setKeyEncAlgo(Encryptor.keyAlgorithm(config.keyEncryptionAlgorithm));
            encrypt.setDigestAlgorithm(Encryptor.oaepDigestAlgorithm(config.oaepDigest));
            encrypt.setMGFAlgorithm(Encryptor.oaepMgfAlgorithm(config.oaepDigest));
            encrypt.setAttachmentCallbackHandler(encryptHandler);
            // Both cipher values move: the wrapped key in the header and the data in the body.
            encrypt.setStoreBytesInAttachment(config.storeBytesInAttachment);

            if (config.requireEncryption) {
                encrypt.getParts().add(
                        new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace(document), "Content"));
            }
            if (config.encryptAttachments) {
                encrypt.getParts().add(
                        new WSEncryptionPart(ALL_ATTACHMENTS, config.attachmentEncryptionCoverage));
            }

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey sessionKey = keyGen.generateKey();

            encrypt.build(crypto, sessionKey);
            if (config.encryptAttachments) {
                // The xenc:EncryptedData elements describing the attachments are produced separately from the
                // in-document ones and have to be attached to the header explicitly.
                encrypt.addAttachmentEncryptedDataElements();
            }

            // Merged rather than replaced. WSS4J hands back the parts it touched, which under
            // storeBytesInAttachment alone is the minted cipher part and nothing else: taking the results as
            // the new list would drop every attachment the message actually arrived with.
            current = merge(current, encryptHandler.results());
        }

        return emit(document, current, protocol);
    }

    /**
     * The attachments as they stand after a WSS4J pass: the ones it handed back, plus the ones it left alone.
     *
     * A transformed part replaces the one it came from, matched on its bare id, and a part WSS4J minted is
     * simply new. Order follows the message, with anything minted last, which is where a peer writing this
     * shape puts it.
     */
    /**
     * The symmetric-binding shape with attachments: one session key, wrapped to the recipient once, keying an
     * HMAC signature and the attachment encryption both. What a peer emits under an sp:SymmetricBinding whose
     * SignedParts and EncryptedParts name the attachments.
     *
     * <p>Its own method rather than a flag threaded through the asymmetric path, because the two differ in what
     * keys each block: there a signature and an encryption are independent blocks that share a header, here they
     * are two uses of one key and the key has to exist before either runs.
     *
     * <p>The reference list lands detached and every xenc:EncryptedData names the key by its EncryptedKeySHA1,
     * which is the pair WSS4J's own reader requires and the only identifier a recipient can compute before it
     * has unwrapped anything.
     */
    private List<Attachment> secureUnderOneKey(Document document, WSSecHeader header, List<Attachment> parts)
            throws Exception {

        org.apache.xml.security.Init.init();

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        SecretKey sessionKey = generator.generateKey();

        WSSecEncryptedKey encryptedKey = new WSSecEncryptedKey(header);
        encryptedKey.setUserInfo(config.encryptionRecipientAlias);
        encryptedKey.setKeyIdentifierType(Encryptor.keyIdentifierType(config.encryptionKeyReference));
        encryptedKey.setKeyEncAlgo(Encryptor.keyAlgorithm(config.keyEncryptionAlgorithm));
        encryptedKey.setDigestAlgorithm(Encryptor.oaepDigestAlgorithm(config.oaepDigest));
        encryptedKey.setMGFAlgorithm(Encryptor.oaepMgfAlgorithm(config.oaepDigest));
        encryptedKey.prepare(crypto, sessionKey);

        AttachmentCallbackHandler signHandler = new AttachmentCallbackHandler(parts);
        if (config.signAttachments) {
            WSSecSignature signature = new WSSecSignature(header);
            signature.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
            signature.setEncrKeySha1value(encryptedKey.getEncryptedKeySHA1());
            signature.setSecretKey(sessionKey.getEncoded());
            signature.setSignatureAlgorithm(Signer.signatureAlgorithm(config.signatureAlgorithm));
            signature.setDigestAlgo(WSConstants.SHA256);
            signature.setSigCanonicalization(Signer.canonicalizationUri(config.canonicalization));
            signature.setAttachmentCallbackHandler(signHandler);

            signature.getParts().add(
                    new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace(document), "Content"));
            if (config.requireTimestamp) {
                signature.getParts().add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, "Element"));
            }
            if (!parts.isEmpty()) {
                signature.getParts().add(
                        new WSEncryptionPart(ALL_ATTACHMENTS, config.attachmentSignatureCoverage));
            }

            signature.build(crypto);
        }

        List<Attachment> current = signHandler.results().isEmpty() ? parts : signHandler.results();

        AttachmentCallbackHandler encryptHandler = new AttachmentCallbackHandler(current);
        if (config.encryptAttachments) {
            WSSecEncrypt encrypt = new WSSecEncrypt(header);
            // The key is already on the wire above, so this references it rather than wrapping a second copy,
            // which is also what makes WSS4J detach the reference list.
            encrypt.setEncryptSymmKey(false);
            encrypt.setKeyIdentifierType(WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER);
            encrypt.setCustomReferenceValue(encryptedKey.getEncryptedKeySHA1());
            encrypt.setSymmetricEncAlgorithm(Encryptor.dataAlgorithm(config.dataEncryptionAlgorithm));
            encrypt.setAttachmentCallbackHandler(encryptHandler);

            if (config.requireEncryption) {
                encrypt.getParts().add(
                        new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace(document), "Content"));
            }
            encrypt.getParts().add(
                    new WSEncryptionPart(ALL_ATTACHMENTS, config.attachmentEncryptionCoverage));

            encrypt.build(crypto, sessionKey);
            encrypt.addAttachmentEncryptedDataElements();

            current = merge(current, encryptHandler.results());
        }

        // Last, so it lands in front of everything that needs it: a reader holds the key by the time the
        // reference list asks it to decrypt.
        encryptedKey.prependToHeader();

        return current;
    }

    private static List<Attachment> merge(List<Attachment> current, List<Attachment> results) {
        if (results.isEmpty()) {
            return current;
        }

        Map<String, Attachment> byId = new LinkedHashMap<>();
        for (Attachment part : current) {
            byId.put(bare(part.getId()), part);
        }
        for (Attachment part : results) {
            byId.put(bare(part.getId()), part);
        }

        return new ArrayList<>(byId.values());
    }

    /** Rebuilds a multipart body from the secured SOAP part and the (possibly transformed) attachments. */
    private Attachments.EmitResult emit(Document document, List<Attachment> parts, String protocol)
            throws Exception {
        MessageFactory factory = MessageFactory.newInstance(soapProtocol(protocol));
        SOAPMessage out;
        try (InputStream soapIn = new ByteArrayInputStream(
                Xml.serialize(document).getBytes(StandardCharsets.UTF_8))) {
            out = factory.createMessage(new MimeHeaders(), soapIn);
        }

        for (Attachment part : parts) {
            byte[] bytes = part.getSourceStream().readAllBytes();
            String mimeType = part.getMimeType() == null ? "application/octet-stream" : part.getMimeType();

            AttachmentPart attachment = out.createAttachmentPart();
            attachment.setRawContentBytes(bytes, 0, bytes.length, mimeType);
            attachment.setContentId("<" + bare(part.getId()) + ">");

            // The headers the part carries after the operation, which after a complete encryption are the
            // minimal ones the profile leaves in the clear. Set explicitly so the far side reads what WSS4J
            // decided rather than what SAAJ would default to.
            if (part.getHeaders() != null) {
                for (Map.Entry<String, String> header : part.getHeaders().entrySet()) {
                    if ("Content-ID".equalsIgnoreCase(header.getKey())
                            || "Content-Type".equalsIgnoreCase(header.getKey())) {
                        continue;
                    }
                    attachment.setMimeHeader(header.getKey(), header.getValue());
                }
            }
            out.addAttachmentPart(attachment);
        }

        out.saveChanges();

        java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        out.writeTo(buffer);
        String[] ctHeader = out.getMimeHeaders().getHeader("Content-Type");

        return new Attachments.EmitResult(
                buffer.toByteArray(),
                (ctHeader != null && ctHeader.length > 0) ? ctHeader[0] : "");
    }

    private SOAPMessage parse(byte[] body, String contentType, String protocol) throws Exception {
        MimeHeaders headers = new MimeHeaders();
        headers.addHeader("Content-Type", contentType);

        try (InputStream in = new ByteArrayInputStream(body)) {
            return MessageFactory.newInstance(soapProtocol(protocol)).createMessage(headers, in);
        }
    }

    /** The message's MIME parts as WSS4J attachments, ids reduced to the bare Content-ID it works with. */
    private static List<Attachment> attachmentsOf(SOAPMessage message) throws Exception {
        List<Attachment> attachments = new ArrayList<>();
        Iterator<?> it = message.getAttachments();
        while (it.hasNext()) {
            AttachmentPart part = (AttachmentPart) it.next();

            Attachment attachment = new Attachment();
            attachment.setId(bare(part.getContentId()));
            attachment.setMimeType(part.getContentType());
            attachment.setSourceStream(new ByteArrayInputStream(part.getRawContentBytes()));

            // Every header the part travelled with, not just the two SAAJ exposes as accessors. A coverage
            // of a part's metadata canonicalizes whatever is here, so dropping a Content-Disposition the
            // sender covered turns into a digest mismatch with nothing to point at.
            Iterator<?> headers = part.getAllMimeHeaders();
            while (headers.hasNext()) {
                jakarta.xml.soap.MimeHeader header = (jakarta.xml.soap.MimeHeader) headers.next();
                attachment.addHeader(header.getName(), header.getValue());
            }
            attachments.add(attachment);
        }

        return attachments;
    }

    private static String bare(String id) {
        if (id == null) {
            return "";
        }
        String bare = id.startsWith("cid:") ? id.substring(4) : id;
        if (bare.startsWith("<") && bare.endsWith(">")) {
            bare = bare.substring(1, bare.length() - 1);
        }

        return bare;
    }

    private static String soapProtocol(String protocol) {
        if (protocol == null || "soap11".equalsIgnoreCase(protocol)) {
            return SOAPConstants.SOAP_1_1_PROTOCOL;
        }
        if ("soap12".equalsIgnoreCase(protocol)) {
            return SOAPConstants.SOAP_1_2_PROTOCOL;
        }
        throw new IllegalArgumentException("Unknown protocol: " + protocol);
    }

    private static String soapNamespace(Document document) {
        String ns = document.getDocumentElement().getNamespaceURI();

        return ns == null ? WSConstants.URI_SOAP12_ENV : ns;
    }

    private static String sha256(byte[] data) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);
        StringBuilder sb = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }

        return sb.toString();
    }
}
