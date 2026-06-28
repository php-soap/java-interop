package org.phpsoap.interop;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.w3c.dom.Document;

import java.util.List;

/**
 * Decrypts a PHP-produced encrypted SOAP message with the Java side's own private key, proving the PHP
 * {@code Outbound\Encryption} block's {@code xenc:EncryptedKey}/{@code xenc:EncryptedData} are wire-format
 * correct against WSS4J. The engine resolves the recipient key from the keystore via the WSSE key reference
 * the PHP side embedded (Subject Key Identifier, BST, IssuerSerial, ...).
 *
 * <p>A {@link CallbackHandlerStub} supplies the keystore password so the engine can unlock the private key.
 */
final class Decryptor {

    private final Crypto crypto;
    private final String keyPassword;

    Decryptor(Crypto crypto, String keyPassword) {
        this.crypto = crypto;
        this.keyPassword = keyPassword;
    }

    Result decrypt(String xml) throws Exception {
        Document document = Xml.parse(xml);

        RequestData data = new RequestData();
        data.setDecCrypto(crypto);
        data.setSigVerCrypto(crypto);
        data.setCallbackHandler(new CallbackHandlerStub(keyPassword));
        data.setWssConfig(org.apache.wss4j.dom.engine.WSSConfig.getNewInstance());

        WSSecurityEngine engine = new WSSecurityEngine();
        WSHandlerResult handlerResult = engine.processSecurityHeader(document, data);
        List<WSSecurityEngineResult> results = handlerResult.getResults();

        boolean sawEncryption = false;
        boolean sawSignature = false;
        for (WSSecurityEngineResult result : results) {
            Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            if (action == null) {
                continue;
            }
            if (action == WSConstants.ENCR) {
                sawEncryption = true;
            }
            if (action == WSConstants.SIGN) {
                sawSignature = true;
            }
        }

        return new Result(sawEncryption, sawSignature, Xml.serialize(document), results.size());
    }

    static final class Result {
        final boolean encryptionProcessed;
        final boolean signatureProcessed;
        final String plaintext;
        final int actionCount;

        Result(boolean encryptionProcessed, boolean signatureProcessed, String plaintext, int actionCount) {
            this.encryptionProcessed = encryptionProcessed;
            this.signatureProcessed = signatureProcessed;
            this.plaintext = plaintext;
            this.actionCount = actionCount;
        }
    }
}
