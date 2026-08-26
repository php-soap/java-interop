<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncKeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use VeeWee\Xml\Dom\Document;

/**
 * The PHP half of the SymmetricBinding round trip.
 *
 * SymmetricBindingInteropTest pins what WSS4J emits and proves its own reader accepts it. This one replaces
 * the emitting half with the php-soap blocks and asks the only question that matters for the wire shape: does
 * WSS4J's reader accept what PHP produces. The two differ in detail, and deliberately so, which is why the
 * question cannot be answered by comparing the two documents.
 *
 * Direction: PHP wraps the session key to the java-server certificate, so the oracle holds the private key
 * that unwraps it and can both verify the HMAC and decrypt the Body.
 */
final class SymmetricBindingPhpInteropTest extends InteropTestCase
{
    private const PLAINTEXT_MARKER = 'hello from the interop harness';

    // ----------------------------------------------------------------- PHP -> WSS4J

    public function test_wss4j_verifies_a_php_hmac_signature_keyed_by_a_wrapped_session_key(): void
    {
        $result = $this->verify($this->phpSymmetric(encrypt: false));

        self::assertTrue($result['valid'], 'WSS4J refused the PHP symmetric signature: '.$result['reason']);
    }

    public function test_wss4j_refuses_the_same_php_message_with_a_forged_mac(): void
    {
        // The control. A green round trip could otherwise mean the verifier silently failed to resolve a key
        // and reported nothing, which is exactly the failure this whole file exists to rule out.
        $result = $this->verify($this->forgeSignatureValue($this->phpSymmetric(encrypt: false)));

        self::assertFalse($result['valid']);
        self::assertNotSame('', $result['reason']);
    }

    public function test_wss4j_decrypts_a_php_body_encrypted_under_a_wrapped_session_key(): void
    {
        $response = Oracle::post('/decrypt', $this->phpSymmetric(sign: false));

        self::assertSame(200, $response['status'], 'oracle /decrypt failed: '.$response['body']);
        self::assertStringContainsString(self::PLAINTEXT_MARKER, $response['body']);
    }

    /**
     * The shape the whole design turns on: one xenc:EncryptedKey, an HMAC signature keyed by it, and the
     * xenc:ReferenceList standing beside it rather than nested inside it.
     */
    public function test_wss4j_reads_a_php_signature_and_encryption_sharing_one_key(): void
    {
        $result = $this->verify($this->phpSymmetric());

        self::assertTrue($result['valid'], 'WSS4J refused the PHP shared-key binding: '.$result['reason']);
    }

    public function test_wss4j_reads_a_php_message_whose_blocks_each_derive_their_own_key(): void
    {
        $result = $this->verify($this->phpSymmetric(derivedKeys: true));

        self::assertTrue($result['valid'], 'WSS4J refused the PHP derived-key binding: '.$result['reason']);
    }

    public function test_wss4j_reads_a_php_symmetric_binding_endorsed_by_a_certificate(): void
    {
        // What makes the request authenticate anybody: the session key was wrapped under the server's public
        // certificate, which anyone holding it can do, so the endorsement is the only part that proves an
        // identity.
        $result = $this->verify($this->phpSymmetric(endorse: true));

        self::assertTrue($result['valid'], 'WSS4J refused the endorsed binding: '.$result['reason']);
    }

    /**
     * What a real sp:Basic128Rsa15 policy pins, which is the suite issue #9's service asks for: HMAC-SHA1 for
     * the signature and AES-128-CBC for the data. Both are refused by the default CryptoPolicy and have to be
     * named, so this is also the row proving the opt-in reaches a message a real peer reads.
     */
    public function test_wss4j_reads_a_php_binding_using_the_legacy_algorithm_suite(): void
    {
        $document = Document::fromXmlString(Oracle::sampleEnvelope());
        $profile = new SecurityProfile(crypto: new CryptoPolicy(
            acceptedSignatureMethods: [SignatureMethod::HMAC_SHA1],
            acceptedDataEncryptionMethods: [DataEncryptionMethod::AES128_CBC],
        ));
        $context = new WsseContext($document, SoapVersion::Soap12, $profile, new ExchangeKeys());

        $sessionKey = new Keys\WrappedSessionKey(
            Certificate::fromFile(Oracle::certPath('java-server.crt')),
            EncKeyRef::Thumbprint,
            DataEncryptionMethod::AES128_CBC,
        );

        (new Outbound\Timestamp())($context);
        (new Outbound\Signature(new Outbound\SymmetricSigningKey($sessionKey)))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA1)
            ->withParts([Part::body(), Part::timestamp()])($context);
        (new Outbound\Encryption($sessionKey))
            ->withDataEncryptionMethod(DataEncryptionMethod::AES128_CBC)
            ->withParts([Part::body()])($context);

        $result = $this->verify($document->toXmlString());

        self::assertTrue($result['valid'], 'WSS4J refused the legacy suite: '.$result['reason']);
    }

    // ----------------------------------------------------------------- WSS4J -> PHP

    /**
     * The direction a client actually experiences: a response keyed by the key its own request conveyed.
     *
     * The oracle answers by processing the request, unwrapping the session key with its private key, and
     * signing and encrypting the answer under that same key. No xenc:EncryptedKey travels back, so PHP resolves
     * the key from what the exchange established, which is the whole point of scoping the keys to an exchange.
     */
    public function test_php_reads_a_wss4j_response_keyed_by_the_key_its_request_established(): void
    {
        $keys = new ExchangeKeys();
        $response = $this->wss4jResponseTo($this->establishedRequest($keys));

        // The same exchange keys the request used, which is what the middleware hands both directions.
        $inbound = $this->context($response, $keys);
        (new Inbound\Decrypt())($inbound);
        (new Inbound\VerifySignature($this->trustStore(), signed: [Part::body()]))($inbound);

        self::assertStringContainsString(self::PLAINTEXT_MARKER, $response->toXmlString());
    }

    /**
     * The same direction with sp:RequireDerivedKeys on, which is the shape this package's reader had never been
     * fed by anything but its own writer. WSS4J's wsc:DerivedKeyToken differs from ours in two ways that matter
     * to a reader: it declares no @Algorithm, relying on the specification's P_SHA1 default, and it carries no
     * wsc:Label, relying on the default label. Requiring either would leave every token it emits unreadable.
     */
    public function test_php_reads_a_wss4j_response_that_derives_a_key_per_block(): void
    {
        $keys = new ExchangeKeys();
        $response = $this->wss4jResponseTo($this->establishedRequest($keys), derivedKeys: true);

        $inbound = $this->context($response, $keys);
        (new Inbound\Decrypt())($inbound);
        (new Inbound\VerifySignature($this->trustStore(), signed: [Part::body()]))($inbound);

        self::assertStringContainsString(self::PLAINTEXT_MARKER, $response->toXmlString());
        self::assertStringContainsString('DerivedKeyToken', $response->toXmlString());
    }

    public function test_php_refuses_that_same_response_against_a_different_exchange(): void
    {
        // The scoping rule, from the outside: a response opens against the exchange that established its key
        // and against no other. Without that a captured answer would replay into any later call.
        $response = $this->wss4jResponseTo($this->establishedRequest(new ExchangeKeys()));

        $this->expectException(SecurityFault::class);
        (new Inbound\Decrypt())($this->context($response, new ExchangeKeys()));
    }

    /** A request that establishes a session key in the given exchange, as a real one would. */
    private function establishedRequest(ExchangeKeys $keys): string
    {
        $document = Document::fromXmlString(Oracle::sampleEnvelope());
        $context = $this->context($document, $keys);

        $sessionKey = new Keys\WrappedSessionKey(
            Certificate::fromFile(Oracle::certPath('java-server.crt')),
            EncKeyRef::Thumbprint,
        );
        (new Outbound\Timestamp())($context);
        (new Outbound\Signature(new Outbound\SymmetricSigningKey($sessionKey)))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body(), Part::timestamp()])($context);
        (new Outbound\Encryption($sessionKey))->withParts([Part::body()])($context);

        return $document->toXmlString();
    }

    /** The oracle's answer, keyed by the key that request conveyed. */
    private function wss4jResponseTo(string $request, bool $derivedKeys = false): Document
    {
        $answered = Oracle::post(
            sprintf('/symmetric/respond?sigalg=HMAC_SHA256&derivedkeys=%s', $derivedKeys ? 'true' : 'false'),
            $request,
        );
        self::assertSame(200, $answered['status'], 'oracle /symmetric/respond failed: '.$answered['body']);
        self::assertStringNotContainsString(
            self::PLAINTEXT_MARKER,
            $answered['body'],
            'the answer is not encrypted',
        );

        return Document::fromXmlString($answered['body']);
    }

    /**
     * A key the peer minted and wrapped to us authenticates nobody, so a signature keyed by it must not verify
     * here however well-formed it is.
     *
     * Anyone holding our public certificate can mint a session key, wrap it to us, and MAC a message with it.
     * Only a key we minted ourselves says something, because only the holder of the recipient private key
     * could have unwrapped it. So the refusal below is the design working, not a missing feature: PHP resolves
     * a symmetric signature against keys this exchange established outbound and against nothing else.
     */
    public function test_php_refuses_a_wss4j_symmetric_signature_keyed_by_a_key_it_did_not_establish(): void
    {
        $signed = Oracle::post(
            '/sign?symmetric=true&sigalg=HMAC_SHA256&derivedkeys=false&recipient=php-client',
            Oracle::sampleEnvelope(),
        );
        self::assertSame(200, $signed['status'], 'oracle /sign failed: '.$signed['body']);

        $document = Document::fromXmlString($signed['body']);
        $context = new WsseContext($document, SoapVersion::Soap12, $this->profile());

        // Decrypt first, as the inbound order requires: it unwraps the key with our private key and opens the
        // Body. That is a key we can read, and still not one we established.
        (new Inbound\Decrypt(Key::fromFile(Oracle::certPath('php-client.key'))))($context);
        self::assertStringContainsString(self::PLAINTEXT_MARKER, $document->toXmlString());

        $this->expectException(SecurityFault::class);
        (new Inbound\VerifySignature($this->trustStore(), signed: [Part::body()]))($context);
    }

    /**
     * The endorsed message, read back by PHP. Both signatures verify: the primary HMAC against the key this
     * exchange established, and the endorsement against the client certificate. This is the shape the verifier
     * refused before it learned to check every signature in its scope rather than exactly one.
     */
    public function test_php_reads_back_its_own_endorsed_binding(): void
    {
        $keys = new ExchangeKeys();
        $document = Document::fromXmlString(Oracle::sampleEnvelope());
        $context = $this->context($document, $keys);

        $sessionKey = new Keys\WrappedSessionKey(
            Certificate::fromFile(Oracle::certPath('java-server.crt')),
            EncKeyRef::Thumbprint,
        );
        (new Outbound\Timestamp())($context);
        (new Outbound\Signature(new Outbound\SymmetricSigningKey($sessionKey)))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body(), Part::timestamp()])($context);
        (new Outbound\Signature(new Outbound\CertificateSigningKey(
            ClientCertificate::fromFile(Oracle::certPath('php-client.pem')),
            KeyRef::BinarySecurityToken,
        )))->withParts([Part::primarySignature()])($context);

        // WSS4J accepts it, and so does this package: the same bytes, read by both.
        self::assertTrue($this->verify($document->toXmlString())['valid']);

        (new Inbound\VerifySignature($this->trustStore(), signed: [Part::body(), Part::timestamp()]))(
            $this->context($document, $keys),
        );
    }

    // ----------------------------------------------------------------- helpers

    /**
     * A PHP symmetric-binding message: the session key wrapped to the oracle's own certificate, an HMAC
     * signature keyed by it, and the Body encrypted under it.
     */
    private function phpSymmetric(
        bool $sign = true,
        bool $encrypt = true,
        bool $derivedKeys = false,
        bool $endorse = false,
    ): string {
        $document = Document::fromXmlString(Oracle::sampleEnvelope());
        $context = new WsseContext($document, SoapVersion::Soap12, $this->profile());

        // One object handed to both blocks is what makes them share a key. Thumbprint because WSS4J resolves it
        // without needing the certificate in the message.
        $sessionKey = new Keys\WrappedSessionKey(
            Certificate::fromFile(Oracle::certPath('java-server.crt')),
            EncKeyRef::Thumbprint,
            // AES-128 so the two blocks disagree about width unless each derives its own key, which is what
            // makes the derived-keys row a different message rather than the same one twice.
            $derivedKeys ? DataEncryptionMethod::AES128_GCM : null,
        );

        (new Outbound\Timestamp())($context);

        if ($sign) {
            $signingKey = $derivedKeys ? new Keys\DerivedSessionKey($sessionKey) : $sessionKey;
            (new Outbound\Signature(new Outbound\SymmetricSigningKey($signingKey)))
                ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
                ->withParts([Part::body(), Part::timestamp()])($context);
        }

        if ($encrypt) {
            $encryptionKey = $derivedKeys ? new Keys\DerivedSessionKey($sessionKey) : $sessionKey;
            $encryption = (new Outbound\Encryption($encryptionKey))->withParts([Part::body()]);
            if ($derivedKeys) {
                $encryption = $encryption->withDataEncryptionMethod(DataEncryptionMethod::AES128_GCM);
            }
            $encryption($context);
        }

        if ($endorse) {
            (new Outbound\Signature(new Outbound\CertificateSigningKey(
                ClientCertificate::fromFile(Oracle::certPath('php-client.pem')),
                KeyRef::BinarySecurityToken,
            )))->withParts([Part::primarySignature()])($context);
        }

        return $document->toXmlString();
    }

    /**
     * HMAC-SHA256 is accepted by default, so the profile only has to name what the derived-keys row needs:
     * AES-128-GCM is on the default list too, which leaves nothing to widen. Spelled out anyway, so a change to
     * the shipped defaults shows up here as a failing assertion rather than as a silently different message.
     */
    private function context(Document $document, ExchangeKeys $keys): WsseContext
    {
        return new WsseContext($document, SoapVersion::Soap12, $this->profile(), $keys);
    }

    private function profile(): SecurityProfile
    {
        return new SecurityProfile(crypto: new CryptoPolicy(
            acceptedSignatureMethods: [SignatureMethod::HMAC_SHA256, SignatureMethod::RSA_SHA256],
            acceptedDataEncryptionMethods: [DataEncryptionMethod::AES128_GCM, DataEncryptionMethod::AES256_GCM],
        ));
    }

    private function trustStore(): TrustStore
    {
        return TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('ca.crt')));
    }

    /**
     * @return array{valid:bool, reason:string}
     */
    private function verify(string $xml): array
    {
        $response = Oracle::post('/verify', $xml);

        self::assertSame(200, $response['status'], 'oracle /verify failed: '.$response['body']);

        $decoded = json_decode($response['body'], true, flags: JSON_THROW_ON_ERROR);

        return ['valid' => (bool) $decoded['valid'], 'reason' => (string) ($decoded['reason'] ?? '')];
    }

    /**
     * Flip the leading base64 character of the ds:SignatureValue, which always changes its first byte and so
     * always breaks the MAC, however the rest of the value happens to be padded.
     */
    private function forgeSignatureValue(string $xml): string
    {
        $dom = new \DOMDocument();
        $dom->loadXML($xml);
        $xpath = new \DOMXPath($dom);
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');

        $value = $xpath->query('//ds:SignatureValue')->item(0);
        self::assertInstanceOf(\DOMElement::class, $value);

        $encoded = $value->textContent;
        $value->textContent = ($encoded[0] === 'A' ? 'B' : 'A').substr($encoded, 1);

        return (string) $dom->saveXML();
    }
}
