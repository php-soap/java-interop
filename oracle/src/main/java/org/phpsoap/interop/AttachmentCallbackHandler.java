package org.phpsoap.interop;

import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Hands WSS4J the message's attachments and collects the ones it hands back.
 *
 * <p>This is the piece the harness was missing. WSS4J does not read a multipart body itself: signing,
 * verifying, encrypting and decrypting an attachment all go through these two callbacks, so without a handler
 * that answers them WSS4J simply has no attachment to work on and reports nothing.
 *
 * <p>{@link AttachmentRequestCallback} asks for the attachments, either all of them or one by id.
 * {@link AttachmentResultCallback} delivers a transformed one back: the ciphertext after encryption, the
 * plaintext after decryption. The results are kept in insertion order so a caller can report them.
 *
 * <p>Ids are normalised on the way in and out. WSS4J works with the bare Content-ID while the SOAP part
 * addresses it as {@code cid:<id>} and a MIME header writes it as {@code <id>}, so all three forms are
 * accepted for a lookup and the bare form is what is stored.
 */
final class AttachmentCallbackHandler implements CallbackHandler {

    private final List<Attachment> attachments;
    private final Map<String, Attachment> results = new LinkedHashMap<>();

    AttachmentCallbackHandler(List<Attachment> attachments) {
        this.attachments = new ArrayList<>(attachments);
    }

    /** The attachments WSS4J produced, in the order it produced them. Empty until it has done work. */
    List<Attachment> results() {
        return new ArrayList<>(results.values());
    }

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof AttachmentRequestCallback request) {
                request.setAttachments(requested(request.getAttachmentId()));
            } else if (callback instanceof AttachmentResultCallback result) {
                Attachment attachment = result.getAttachment();
                results.put(normalise(result.getAttachmentId()), attachment);
            } else {
                throw new UnsupportedCallbackException(callback, "Unsupported attachment callback");
            }
        }
    }

    /**
     * WSS4J's part list names {@code cid:Attachments} to mean "every attachment on this message", and passes
     * that through {@code AttachmentUtils.getAttachmentId}, which strips the scheme. So what arrives here is
     * the literal id {@code Attachments}, and treating it as a Content-ID to look up finds nothing: the
     * signature comes out with no attachment reference at all and nothing reports a problem.
     *
     * An absent or empty id means the same thing.
     */
    private static final String ALL = "Attachments";

    private List<Attachment> requested(String id) {
        String wanted = normalise(id);
        if (wanted.isEmpty() || ALL.equals(wanted)) {
            List<Attachment> all = new ArrayList<>();
            for (Attachment candidate : attachments) {
                all.add(current(normalise(candidate.getId()), candidate));
            }

            return all;
        }

        List<Attachment> matching = new ArrayList<>();
        for (Attachment candidate : attachments) {
            String candidateId = normalise(candidate.getId());
            if (candidateId.equals(wanted)) {
                matching.add(current(candidateId, candidate));
            }
        }

        return matching;
    }

    /**
     * The latest form of an attachment: whatever a previous callback delivered back, or the original.
     *
     * This matters for one message per protection order. Verifying a sign-then-encrypt message asks twice:
     * the EncryptedKey is processed first and delivers the decrypted attachment, then the signature asks for
     * the attachment to digest. Answering the second question with the ciphertext makes every attachment
     * digest fail, which surfaces as a bare signature failure and says nothing about why.
     */
    private Attachment current(String id, Attachment original) {
        return results.getOrDefault(id, original);
    }

    private static String normalise(String id) {
        if (id == null) {
            return "";
        }

        String bare = id;
        if (bare.startsWith("cid:")) {
            bare = bare.substring(4);
        }
        if (bare.startsWith("<") && bare.endsWith(">")) {
            bare = bare.substring(1, bare.length() - 1);
        }

        return bare;
    }
}
