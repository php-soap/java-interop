package org.phpsoap.interop;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.w3c.dom.Document;

import javax.crypto.spec.SecretKeySpec;
import java.util.List;

/**
 * Answers a symmetric-binding request the way a real service does: with the key the request conveyed, rather
 * than one of its own.
 *
 * <p>This is the direction the rest of the harness could not reach. A client verifies a symmetric response
 * against a key it established itself, because a key the peer minted and wrapped to that client authenticates
 * nobody: anyone holding the client's public certificate can mint one. So an oracle that always mints its own
 * key can only ever produce responses a correct client refuses, which proves nothing about the client's
 * accepting path.
 *
 * <p>The request is processed first, which unwraps the {@code xenc:EncryptedKey} with the server's private key
 * and yields the session key. The response is then signed and encrypted under that same key and carries no
 * {@code xenc:EncryptedKey} at all, since the client already has it.
 */
final class SymmetricResponder {

    /**
     * What the answer says, which is not what is under test: the client's accepting path is. It carries a
     * marker so a test can tell decrypted content from ciphertext without parsing anything.
     */
    static final String RESPONSE_ENVELOPE =
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\">"
            + "<soap:Header/>"
            + "<soap:Body><tns:PingResponse xmlns:tns=\"urn:php-soap:interop\">"
            + "<tns:message>hello from the interop harness</tns:message>"
            + "</tns:PingResponse></soap:Body>"
            + "</soap:Envelope>";

    private final Crypto crypto;
    private final ScenarioConfig config;
    private final String keyPassword;

    SymmetricResponder(Crypto crypto, ScenarioConfig config, String keyPassword) {
        this.crypto = crypto;
        this.config = config;
        this.keyPassword = keyPassword;
    }

    /**
     * @param requestXml a symmetric-binding request carrying an xenc:EncryptedKey wrapped to this server
     * @param responseXml the envelope to secure as the answer
     */
    String respond(String requestXml, String responseXml) throws Exception {
        org.apache.xml.security.Init.init();

        byte[] sessionKey = sessionKeyOf(requestXml);
        Document response = Xml.parse(responseXml);
        WSSecHeader header = new WSSecHeader(response);
        header.insertSecurityHeader();

        new SymmetricBinding(crypto, config, keyPassword).applyWithEstablishedKey(
                response,
                header,
                List.of(SymmetricBinding.bodyContentPart(response)),
                new SecretKeySpec(sessionKey, "AES"),
                encryptedKeySha1Of(requestXml));

        return Xml.serialize(response);
    }

    /** The session key the request wrapped to us, unwrapped with our own private key. */
    private byte[] sessionKeyOf(String requestXml) throws Exception {
        for (WSSecurityEngineResult result : process(requestXml)) {
            Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            byte[] secret = (byte[]) result.get(WSSecurityEngineResult.TAG_SECRET);
            if (action != null && action == WSConstants.ENCR && secret != null) {
                return secret;
            }
        }

        throw new IllegalArgumentException("the request carries no xenc:EncryptedKey this server can unwrap");
    }

    /**
     * The identifier the response names the key by, which has to be the one the request minted: the digest is
     * over cipher bytes only the request carries, and the response carries no key of its own to digest.
     */
    private String encryptedKeySha1Of(String requestXml) throws Exception {
        for (WSSecurityEngineResult result : process(requestXml)) {
            byte[] wrapped = (byte[]) result.get(WSSecurityEngineResult.TAG_ENCRYPTED_EPHEMERAL_KEY);
            if (wrapped != null) {
                return java.util.Base64.getEncoder()
                        .encodeToString(org.apache.wss4j.common.util.KeyUtils.generateDigest(wrapped));
            }
        }

        throw new IllegalArgumentException("the request carries no wrapped key to name");
    }

    private List<WSSecurityEngineResult> process(String requestXml) throws Exception {
        Document request = Xml.parse(requestXml);

        RequestData data = new RequestData();
        data.setDecCrypto(crypto);
        data.setSigVerCrypto(crypto);
        data.setCallbackHandler(new SessionKeyCallbackHandler(new CallbackHandlerStub(keyPassword), data));
        data.setWssConfig(org.apache.wss4j.dom.engine.WSSConfig.getNewInstance());

        WSHandlerResult handlerResult = new WSSecurityEngine().processSecurityHeader(request, data);

        return handlerResult.getResults();
    }
}
