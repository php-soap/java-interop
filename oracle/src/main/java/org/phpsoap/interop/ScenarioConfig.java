package org.phpsoap.interop;

import java.util.Properties;

/**
 * The set of protections a message must satisfy (when verifying) or carry (when signing).
 *
 * <p>This is the single growth seam of the harness. The happy flow only exercises
 * {@link #requireSignature} + {@link #requireTimestamp}. New scenarios (encryption,
 * UsernameToken, SAML) are added as further flags here and read by {@link Verifier} /
 * {@link Signer}; nothing else in the CLI needs to change.
 */
public final class ScenarioConfig {

    public boolean requireSignature = true;
    public boolean requireTimestamp = true;

    public boolean requireEncryption = false;   // enforce/produce xenc:EncryptedData over the Body

    /**
     * Sign the message's attachments as well, per the WSS SwA Profile: a ds:Reference with a cid: URI and the
     * Attachment-Content-Signature-Transform, in the same ds:Signature as the in-document references. What a
     * {@code sp:Attachments} assertion under {@code sp:SignedParts} asks for.
     */
    public boolean signAttachments = false;

    /**
     * Encrypt the message's attachments as well: one xenc:EncryptedData per attachment carrying an
     * xenc:CipherReference, under the same session key as any in-document parts. What a
     * {@code sp:Attachments} assertion under {@code sp:EncryptedParts} asks for.
     */
    public boolean encryptAttachments = false;

    /**
     * How much of an attachment the signature covers: {@code Content} for its bytes alone, {@code Element}
     * for its canonicalized MIME headers as well. A bare {@code sp:Attachments} means Element, and
     * {@code sp13:ContentSignatureTransform} is what opts out of it, so this is the modifier CXF's
     * {@code getSignedParts()} picks from the policy.
     */
    public String attachmentSignatureCoverage = "Content";

    /** The same choice for encryption, which no policy validates but a default-configured sender emits. */
    public String attachmentEncryptionCoverage = "Content";
    public boolean requireUsernameToken = false; // enforce/produce wsse:UsernameToken
    public boolean requireSaml = false;          // enforce/produce a saml:Assertion in the Security header

    /**
     * Enforce that the signature was made with the key a signed SAML assertion vouches for, rather than merely
     * that an assertion is present. This is the Holder-of-Key binding itself: without it a message could carry
     * an assertion the signature has nothing to do with and still verify.
     */
    public boolean requireSamlHolderOfKey = false;

    /** Keystore alias whose key a issued Holder-of-Key assertion vouches for. The PHP side holds this one. */
    public String samlHolderAlias = "php-client";

    /** Keystore alias an issued assertion is signed with. Must chain to the CA both peers trust. */
    public String samlIssuerAlias = "java-server";

    /** When false the issued assertion carries no signature, which is the refusal case. */
    public boolean samlSignAssertion = true;

    /** Maximum age (seconds) a Created timestamp may have. Mirrors the PHP clockSkew/ttl window. */
    public int timestampTimeToLiveSeconds = 300;
    /** Allowed clock skew (seconds) between the two peers. */
    public int timestampFutureTimeToLiveSeconds = 60;

    /**
     * WSSE key-reference style the signer puts in ds:KeyInfo. One of:
     * BinarySecurityToken (default), SubjectKeyIdentifier, IssuerSerial, Thumbprint.
     * Mirrors the PHP {@code Outbound\KeyRef} enum so each variant can be cross-tested.
     */
    public String signatureKeyReference = "BinarySecurityToken";

    /** XML-DSig signature algorithm: RSA_SHA256 (default), RSA_SHA512 or ECDSA_SHA256. */
    public String signatureAlgorithm = "RSA_SHA256";

    /**
     * When true the signer puts the whole certification path in the wsse:BinarySecurityToken as an
     * ASN.1 SEQUENCE OF Certificate (#X509PKIPathv1) instead of the leaf certificate alone
     * (#X509v3), which is WSS4J's setUseSingleCertificate(false). Mirrors the PHP
     * Outbound\Signature::withCertificatePath() opt-in so both emitters can be cross-tested.
     */
    public boolean signatureCertificatePath = false;

    /**
     * Keystore alias the signer uses. Defaults to the RSA java-server key; the ECDSA-SHA256 rows select the
     * EC leaf (ec-client) so the signature algorithm and key type agree.
     */
    public String signatureKeyAlias = "java-server";

    /**
     * WSSE key-reference style the encryptor puts in the recipient KeyInfo, mirroring the PHP EncKeyRef enum.
     * SubjectKeyIdentifier (default) or IssuerSerial; lets the Java->PHP encryption recipient-resolution
     * variants be cross-tested.
     */
    public String encryptionKeyReference = "SubjectKeyIdentifier";

    /** Keystore alias of the encryption recipient. Defaults to the php-client cert (Java->PHP direction). */
    public String encryptionRecipientAlias = "php-client";

    /**
     * ds:SignedInfo canonicalization: EXCLUSIVE (default, xml-exc-c14n#) or INCLUSIVE
     * (Canonical XML 1.0, REC-xml-c14n-20010315). Lets the harness emit inclusive-C14N
     * signatures so the PHP Inbound\VerifySignature inclusive-C14N path can be cross-tested.
     */
    public String canonicalization = "EXCLUSIVE";

    /**
     * XML-Enc data (bulk) encryption algorithm: AES256_GCM (default) or AES256_CBC.
     * Used by the encrypt command and the require.encryption signer path.
     */
    public String dataEncryptionAlgorithm = "AES256_GCM";

    /** XML-Enc key transport algorithm: RSA_OAEP (default) or RSA_OAEP_MGF1P. */
    public String keyEncryptionAlgorithm = "RSA_OAEP";

    /** OAEP mask/digest parameterization for the key transport: SHA1 (default) or SHA256. */
    public String oaepDigest = "SHA1";

    /** Username for the wsse:UsernameToken (when require.usernameToken). */
    public String username = "interop-user";
    /** Password for the wsse:UsernameToken. */
    public String usernamePassword = "interop-secret";
    /** Emit/expect a PasswordDigest rather than PasswordText. */
    public boolean usernamePasswordDigest = false;

    /**
     * When true the verifier turns off WSS4J's BSP (Basic Security Profile) compliance checks. Some valid
     * XML-DSig key-reference forms the PHP side emits (e.g. ds:X509Data/X509IssuerSerial directly under
     * ds:KeyInfo) are not BSP-compliant; disabling lets the harness test pure wire correctness separately
     * from BSP strictness.
     */
    public boolean disableBspEnforcement = false;

    /** Build a config from a java.util.Properties bag (keys: require.signature, etc.). */
    public static ScenarioConfig fromProperties(Properties props) {
        ScenarioConfig config = new ScenarioConfig();
        config.requireSignature = boolProp(props, "require.signature", config.requireSignature);
        config.requireTimestamp = boolProp(props, "require.timestamp", config.requireTimestamp);
        config.requireEncryption = boolProp(props, "require.encryption", config.requireEncryption);
        config.signAttachments = boolProp(props, "attachments.sign", config.signAttachments);
        config.encryptAttachments = boolProp(props, "attachments.encrypt", config.encryptAttachments);
        config.attachmentSignatureCoverage =
                props.getProperty("attachments.signCoverage", config.attachmentSignatureCoverage).trim();
        config.attachmentEncryptionCoverage =
                props.getProperty("attachments.encryptCoverage", config.attachmentEncryptionCoverage).trim();
        config.requireUsernameToken = boolProp(props, "require.usernameToken", config.requireUsernameToken);
        config.requireSaml = boolProp(props, "require.saml", config.requireSaml);
        config.timestampTimeToLiveSeconds =
                intProp(props, "timestamp.ttl", config.timestampTimeToLiveSeconds);
        config.timestampFutureTimeToLiveSeconds =
                intProp(props, "timestamp.skew", config.timestampFutureTimeToLiveSeconds);
        config.signatureKeyReference =
                props.getProperty("signature.keyReference", config.signatureKeyReference).trim();
        config.signatureAlgorithm =
                props.getProperty("signature.algorithm", config.signatureAlgorithm).trim();
        config.signatureCertificatePath =
                boolProp(props, "signature.certificatePath", config.signatureCertificatePath);
        config.canonicalization =
                props.getProperty("signature.canonicalization", config.canonicalization).trim();
        config.dataEncryptionAlgorithm =
                props.getProperty("encryption.data", config.dataEncryptionAlgorithm).trim();
        config.keyEncryptionAlgorithm =
                props.getProperty("encryption.key", config.keyEncryptionAlgorithm).trim();
        config.oaepDigest =
                props.getProperty("encryption.oaepDigest", config.oaepDigest).trim();
        config.username = props.getProperty("username.name", config.username).trim();
        config.usernamePassword = props.getProperty("username.password", config.usernamePassword);
        config.usernamePasswordDigest =
                boolProp(props, "username.digest", config.usernamePasswordDigest);
        config.disableBspEnforcement =
                boolProp(props, "verify.disableBsp", config.disableBspEnforcement);
        return config;
    }

    private static boolean boolProp(Properties props, String key, boolean fallback) {
        String value = props.getProperty(key);
        return value == null ? fallback : Boolean.parseBoolean(value.trim());
    }

    private static int intProp(Properties props, String key, int fallback) {
        String value = props.getProperty(key);
        return value == null ? fallback : Integer.parseInt(value.trim());
    }

    @Override
    public String toString() {
        return "ScenarioConfig{"
                + "signature=" + requireSignature
                + ", timestamp=" + requireTimestamp
                + ", encryption=" + requireEncryption
                + ", signAttachments=" + signAttachments
                + ", encryptAttachments=" + encryptAttachments
                + ", usernameToken=" + requireUsernameToken
                + ", saml=" + requireSaml
                + ", ttl=" + timestampTimeToLiveSeconds + "s"
                + ", skew=" + timestampFutureTimeToLiveSeconds + "s"
                + '}';
    }
}
