package org.phpsoap.interop;

import jakarta.xml.soap.AttachmentPart;
import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.MimeHeaders;
import jakarta.xml.soap.SOAPConstants;
import jakarta.xml.soap.SOAPMessage;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecEncrypt;
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
import java.util.Iterator;
import java.util.List;

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
        final boolean sawSignature;
        final boolean sawEncryption;

        CheckResult(
                boolean ok,
                List<String> problems,
                List<String> attachmentSha256,
                List<String> rawAttachmentSha256,
                boolean sawSignature,
                boolean sawEncryption) {
            this.ok = ok;
            this.problems = problems;
            this.attachmentSha256 = attachmentSha256;
            this.rawAttachmentSha256 = rawAttachmentSha256;
            this.sawSignature = sawSignature;
            this.sawEncryption = sawEncryption;
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

        AttachmentCallbackHandler attachmentHandler = new AttachmentCallbackHandler(inbound);

        RequestData data = new RequestData();
        data.setSigVerCrypto(crypto);
        data.setDecCrypto(crypto);
        data.setCallbackHandler(new CallbackHandlerStub(KEYSTORE_PASSWORD, config.usernamePassword));
        data.setAttachmentCallbackHandler(attachmentHandler);
        data.setWssConfig(WSSConfig.getNewInstance());
        data.setDisableBSPEnforcement(config.disableBspEnforcement);
        data.setTimeStampTTL(config.timestampTimeToLiveSeconds);
        data.setTimeStampFutureTTL(config.timestampFutureTimeToLiveSeconds);

        WSHandlerResult handlerResult = new WSSecurityEngine().processSecurityHeader(document, data);

        boolean sawSignature = false;
        boolean sawEncryption = false;
        for (WSSecurityEngineResult result : handlerResult.getResults()) {
            Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            if (action == null) {
                continue;
            }
            if (action == WSConstants.SIGN) {
                sawSignature = true;
            }
            if (action == WSConstants.ENCR) {
                sawEncryption = true;
            }
        }

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

        return new CheckResult(problems.isEmpty(), problems, digests, rawDigests, sawSignature, sawEncryption);
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
        if (parts.isEmpty()) {
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

        AttachmentCallbackHandler signHandler = new AttachmentCallbackHandler(parts);
        if (config.signAttachments) {
            WSSecSignature signature = new WSSecSignature(header);
            signature.setUserInfo(config.signatureKeyAlias, KEYSTORE_PASSWORD);
            signature.setKeyIdentifierType(Signer.keyIdentifierType(config.signatureKeyReference));
            signature.setSignatureAlgorithm(Signer.signatureAlgorithm(config.signatureAlgorithm));
            signature.setDigestAlgo(WSConstants.SHA256);
            signature.setSigCanonicalization(Signer.canonicalizationUri(config.canonicalization));
            signature.setAttachmentCallbackHandler(signHandler);

            signature.getParts().add(
                    new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace(document), "Content"));
            if (config.requireTimestamp) {
                signature.getParts().add(new WSEncryptionPart("Timestamp", WSConstants.WSU_NS, "Element"));
            }
            signature.getParts().add(new WSEncryptionPart(ALL_ATTACHMENTS, "Content"));

            signature.build(crypto);
        }

        // The attachments as they stand after signing: unchanged, since a signature only reads them.
        List<Attachment> current = signHandler.results().isEmpty() ? parts : signHandler.results();

        AttachmentCallbackHandler encryptHandler = new AttachmentCallbackHandler(current);
        if (config.encryptAttachments) {
            WSSecEncrypt encrypt = new WSSecEncrypt(header);
            encrypt.setUserInfo(config.encryptionRecipientAlias);
            encrypt.setKeyIdentifierType(Encryptor.keyIdentifierType(config.encryptionKeyReference));
            encrypt.setSymmetricEncAlgorithm(Encryptor.dataAlgorithm(config.dataEncryptionAlgorithm));
            encrypt.setKeyEncAlgo(Encryptor.keyAlgorithm(config.keyEncryptionAlgorithm));
            encrypt.setDigestAlgorithm(Encryptor.oaepDigestAlgorithm(config.oaepDigest));
            encrypt.setMGFAlgorithm(Encryptor.oaepMgfAlgorithm(config.oaepDigest));
            encrypt.setAttachmentCallbackHandler(encryptHandler);

            if (config.requireEncryption) {
                encrypt.getParts().add(
                        new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace(document), "Content"));
            }
            encrypt.getParts().add(new WSEncryptionPart(ALL_ATTACHMENTS, "Content"));

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey sessionKey = keyGen.generateKey();

            encrypt.build(crypto, sessionKey);
            // The xenc:EncryptedData elements describing the attachments are produced separately from the
            // in-document ones and have to be attached to the header explicitly.
            encrypt.addAttachmentEncryptedDataElements();

            current = encryptHandler.results().isEmpty() ? current : encryptHandler.results();
        }

        return emit(document, current, protocol);
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
            attachment.addHeader("Content-Type", part.getContentType());
            attachment.addHeader("Content-ID", part.getContentId());
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
