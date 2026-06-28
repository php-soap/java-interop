package org.phpsoap.interop;

import jakarta.xml.soap.AttachmentPart;
import jakarta.xml.soap.MessageFactory;
import jakarta.xml.soap.MimeHeaders;
import jakarta.xml.soap.SOAPConstants;
import jakarta.xml.soap.SOAPMessage;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

/**
 * SAAJ-backed SwA / MTOM attachment interop, exposed over HTTP by {@link OracleServer}.
 *
 * <p>{@code receive} parses a multipart/related body produced by the PHP RequestBuilder and reports
 * the attachment count, each attachment's raw-byte SHA-256, and the root SOAP part. For MTOM this
 * proves SAAJ resolves the {@code xop:Include}'d binary as a first-class attachment.
 *
 * <p>{@code emit} builds a multipart/related body (SwA or MTOM) for the PHP ResponseBuilder to consume.
 * SwA uses SAAJ's native multipart emission. MTOM emission is not exposed by the standard SAAJ public
 * API (no WRITE_XOP_INCLUDE flag in jakarta.xml.soap), so the MTOM case hand-constructs a spec-correct
 * application/xop+xml multipart whose root part is the SOAP envelope as supplied (it must already
 * contain the xop:Include) and whose second part is the raw binary.
 */
final class Attachments {

    private static final String MAIN_CID = "<soaprequest@main>";

    private Attachments() {
    }

    /** Result of parsing an inbound multipart body: attachment SHA-256 list + the root SOAP part. */
    static final class ReceiveResult {
        final int count;
        final List<String> sha256;
        final String soapXml;

        ReceiveResult(int count, List<String> sha256, String soapXml) {
            this.count = count;
            this.sha256 = sha256;
            this.soapXml = soapXml;
        }
    }

    /** Result of building an outbound multipart body: the bytes plus the Content-Type header to send. */
    static final class EmitResult {
        final byte[] body;
        final String contentType;

        EmitResult(byte[] body, String contentType) {
            this.body = body;
            this.contentType = contentType;
        }
    }

    static ReceiveResult receive(byte[] body, String contentType, String protocol) throws Exception {
        MimeHeaders headers = new MimeHeaders();
        headers.addHeader("Content-Type", contentType);

        SOAPMessage message;
        try (InputStream in = new ByteArrayInputStream(body)) {
            message = MessageFactory.newInstance(soapProtocol(protocol)).createMessage(headers, in);
        }

        List<String> hashes = new ArrayList<>();
        Iterator<?> it = message.getAttachments();
        while (it.hasNext()) {
            AttachmentPart part = (AttachmentPart) it.next();
            hashes.add(sha256(part.getRawContentBytes()));
        }

        return new ReceiveResult(message.countAttachments(), hashes, soapPartToString(message));
    }

    static EmitResult emit(String type, String protocol, byte[] soapBytes, byte[] attachmentBytes, String cid)
            throws Exception {
        if ("mtom".equals(type.toLowerCase(Locale.ROOT))) {
            return emitMtom(protocol, soapBytes, attachmentBytes, cid);
        }
        return emitSwa(protocol, soapBytes, attachmentBytes, cid);
    }

    private static EmitResult emitSwa(String protocol, byte[] soapBytes, byte[] attachmentBytes, String cid)
            throws Exception {
        MessageFactory factory = MessageFactory.newInstance(soapProtocol(protocol));
        SOAPMessage message;
        try (InputStream soapIn = new ByteArrayInputStream(soapBytes)) {
            message = factory.createMessage(new MimeHeaders(), soapIn);
        }

        AttachmentPart attachment = message.createAttachmentPart();
        attachment.setRawContentBytes(attachmentBytes, 0, attachmentBytes.length, "application/octet-stream");
        attachment.setContentId("<" + cid + ">");
        message.addAttachmentPart(attachment);
        message.saveChanges();

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        message.writeTo(buffer);

        String[] ctHeader = message.getMimeHeaders().getHeader("Content-Type");
        String contentType = (ctHeader != null && ctHeader.length > 0) ? ctHeader[0] : "";

        return new EmitResult(buffer.toByteArray(), contentType);
    }

    /**
     * Hand-constructed MTOM multipart. The standard SAAJ API does not expose XOP emission, so this writes
     * a spec-correct application/xop+xml package directly. The root part is the SOAP envelope as supplied
     * (caller must have inlined the xop:Include href="cid:ID") and the binary part's Content-ID is &lt;ID&gt;.
     */
    private static EmitResult emitMtom(String protocol, byte[] soapBytes, byte[] attachmentBytes, String cid)
            throws Exception {
        String soapContentType = "soap12".equalsIgnoreCase(protocol)
                ? "application/soap+xml"
                : "text/xml";
        String boundary = "----=_Part_interop_" + System.nanoTime();

        String contentType = "multipart/related; type=\"application/xop+xml\"; boundary=\"" + boundary
                + "\"; start=\"" + MAIN_CID + "\"; start-info=\"" + soapContentType + "\"";

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        String crlf = "\r\n";

        // Root part: application/xop+xml wrapping the SOAP envelope.
        body.write(("--" + boundary + crlf).getBytes(StandardCharsets.UTF_8));
        body.write(("Content-Type: application/xop+xml; charset=UTF-8; type=\"" + soapContentType + "\"" + crlf)
                .getBytes(StandardCharsets.UTF_8));
        body.write(("Content-Transfer-Encoding: 8bit" + crlf).getBytes(StandardCharsets.UTF_8));
        body.write(("Content-ID: " + MAIN_CID + crlf).getBytes(StandardCharsets.UTF_8));
        body.write(crlf.getBytes(StandardCharsets.UTF_8));
        body.write(soapBytes);
        body.write(crlf.getBytes(StandardCharsets.UTF_8));

        // Binary part.
        body.write(("--" + boundary + crlf).getBytes(StandardCharsets.UTF_8));
        body.write(("Content-Type: application/octet-stream" + crlf).getBytes(StandardCharsets.UTF_8));
        body.write(("Content-Transfer-Encoding: binary" + crlf).getBytes(StandardCharsets.UTF_8));
        body.write(("Content-ID: <" + cid + ">" + crlf).getBytes(StandardCharsets.UTF_8));
        body.write(crlf.getBytes(StandardCharsets.UTF_8));
        body.write(attachmentBytes);
        body.write(crlf.getBytes(StandardCharsets.UTF_8));

        body.write(("--" + boundary + "--" + crlf).getBytes(StandardCharsets.UTF_8));

        return new EmitResult(body.toByteArray(), contentType);
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

    private static String soapPartToString(SOAPMessage message) throws Exception {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(message.getSOAPPart()), new StreamResult(writer));
        return writer.toString();
    }

    private static String sha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        StringBuilder sb = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
