package org.phpsoap.interop;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.w3c.dom.Document;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Runs WSS4J's {@link WSSecurityEngine} over an inbound message and asserts that the protections
 * required by {@link ScenarioConfig} are actually present and valid.
 *
 * <p>WSS4J reports what it FOUND; it does not, on its own, fail because something is MISSING. So the
 * required-parts check is ours: we walk the engine results and confirm a SIGN action and a TIMESTAMP
 * action are present when the scenario requires them. This mirrors the PHP
 * {@code Inbound\VerifySignature} + {@code Inbound\ValidateTimestamp} required-coverage logic.
 */
final class Verifier {

    private final Crypto crypto;
    private final ScenarioConfig config;

    Verifier(Crypto crypto, ScenarioConfig config) {
        this.crypto = crypto;
        this.config = config;
    }

    Result verify(String xml) throws Exception {
        Document document = Xml.parse(xml);

        RequestData data = new RequestData();
        data.setSigVerCrypto(crypto);
        data.setDecCrypto(crypto);
        data.setCallbackHandler(new CallbackHandlerStub("changeit", config.usernamePassword));
        data.setWssConfig(org.apache.wss4j.dom.engine.WSSConfig.getNewInstance());
        data.setDisableBSPEnforcement(config.disableBspEnforcement);
        // Freshness window for the wsu:Timestamp, matching the PHP profile's ttl/skew.
        data.setTimeStampTTL(config.timestampTimeToLiveSeconds);
        data.setTimeStampFutureTTL(config.timestampFutureTimeToLiveSeconds);

        WSSecurityEngine engine = new WSSecurityEngine();
        WSHandlerResult handlerResult = engine.processSecurityHeader(document, data);
        List<WSSecurityEngineResult> results = handlerResult.getResults();

        List<String> problems = new ArrayList<>();
        boolean sawSignature = false;
        boolean sawTimestamp = false;
        boolean sawEncryption = false;
        boolean sawUsernameToken = false;
        boolean sawSamlAssertion = false;
        boolean samlHolderOfKey = false;
        String signerSubject = null;

        for (WSSecurityEngineResult result : results) {
            Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            if (action == null) {
                continue;
            }
            if (action == WSConstants.SIGN) {
                sawSignature = true;
                X509Certificate cert =
                        (X509Certificate) result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
                if (cert != null) {
                    signerSubject = cert.getSubjectX500Principal().getName();
                }
            }
            if (action == WSConstants.TS) {
                sawTimestamp = true;
            }
            if (action == WSConstants.ENCR) {
                sawEncryption = true;
            }
            if (action == WSConstants.UT || action == WSConstants.UT_NOPASSWORD) {
                sawUsernameToken = true;
            }
            // ST_SIGNED is an assertion whose own signature verified against the trust store; ST_UNSIGNED is one
            // that carried none. Only the former can vouch for a key, so the two are tracked apart.
            if (action == WSConstants.ST_SIGNED || action == WSConstants.ST_UNSIGNED) {
                sawSamlAssertion = true;
                Object token = result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
                if (action == WSConstants.ST_SIGNED && token instanceof SamlAssertionWrapper assertion) {
                    samlHolderOfKey = assertion.getConfirmationMethods().stream()
                            .anyMatch(method -> method != null && method.contains("holder-of-key"));
                }
            }
        }

        if (config.requireSignature && !sawSignature) {
            problems.add("required signature is missing (no SIGN action in the Security header)");
        }
        if (config.requireTimestamp && !sawTimestamp) {
            problems.add("required timestamp is missing (no wsu:Timestamp in the Security header)");
        }
        if (config.requireEncryption && !sawEncryption) {
            problems.add("required encryption is missing (no xenc:EncryptedData processed)");
        }
        if (config.requireUsernameToken && !sawUsernameToken) {
            problems.add("required UsernameToken is missing (no wsse:UsernameToken processed)");
        }
        if (config.requireSaml && !sawSamlAssertion) {
            problems.add("required SAML assertion is missing (no saml:Assertion processed)");
        }
        // The point of Holder-of-Key is that the signature was made with the key the assertion vouches for.
        // WSS4J proves that by resolving the signing key THROUGH the assertion, so a signature that verified
        // beside a holder-of-key assertion is the binding; an assertion present but not confirming holder-of-key
        // means the reference was decorative and the signer was trusted on some other ground.
        if (config.requireSamlHolderOfKey && !samlHolderOfKey) {
            problems.add("required SAML Holder-of-Key confirmation is missing "
                    + "(no signed assertion with a holder-of-key subject confirmation)");
        }

        return new Result(problems.isEmpty(), problems, sawSignature, sawTimestamp, signerSubject, results.size());
    }

    /** Outcome of a verification run, used for human-readable reporting and a process exit code. */
    static final class Result {
        final boolean ok;
        final List<String> problems;
        final boolean signaturePresent;
        final boolean timestampPresent;
        final String signerSubject;
        final int actionCount;

        Result(boolean ok, List<String> problems, boolean signaturePresent,
               boolean timestampPresent, String signerSubject, int actionCount) {
            this.ok = ok;
            this.problems = problems;
            this.signaturePresent = signaturePresent;
            this.timestampPresent = timestampPresent;
            this.signerSubject = signerSubject;
            this.actionCount = actionCount;
        }
    }
}
