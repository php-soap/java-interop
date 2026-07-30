<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use PHPUnit\Framework\Attributes\DataProvider;
use Psl\DateTime\Timestamp;
use Psl\DateTime\Timezone;
use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use SoapInterop\Tests\Support\Wsse;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\Clock\Clock;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use VeeWee\Xml\Dom\Document;

/**
 * Signing interop, both directions, between the php-soap http-wsse-middleware and the WSS4J oracle.
 *
 * Positive rows assert mutual acceptance; negative rows assert explicit rejection (a negative that
 * silently passes is the dangerous failure, so each negative proves the bad message was refused).
 */
final class SignatureInteropTest extends InteropTestCase
{
    // ----------------------------------------------------------------- positive: PHP -> Java

    public function test_php_signed_happy_flow_is_accepted_by_wss4j(): void
    {
        $signed = Wsse::sign();

        $response = Oracle::post('/verify', $signed);

        self::assertSame(200, $response['status']);
        self::assertJsonStringEqualsJsonString('{"valid":true}', $response['body']);
    }

    public function test_php_signed_certificate_path_is_accepted_by_wss4j(): void
    {
        // The BinarySecurityToken carries the leaf and the CA as one ASN.1 SEQUENCE OF Certificate
        // (#X509PKIPathv1) instead of the leaf alone. This row is what settles the byte order: our own reader
        // derives the end-entity from issuer linkage and so accepts either direction, while WSS4J refuses a
        // leaf-first path outright ("CA key usage check failed: keyCertSign bit is not set" -- it reads the
        // first certificate as the issuer). Anchor first, as ITU-T X.509 defines a PkiPath, is what passes.
        $signed = Wsse::sign(certificatePath: true);

        $response = Oracle::post('/verify', $signed);

        self::assertValid($response, 'WSS4J should verify a PHP signature advertising a certification path');
    }

    public function test_php_signed_soap11_is_accepted_by_wss4j(): void
    {
        $signed = Wsse::sign(
            soapVersion: SoapVersion::Soap11,
            inputXml: (string) file_get_contents(dirname(__DIR__, 2) . '/samples/request-unsigned-soap11.xml'),
        );

        $response = Oracle::post('/verify', $signed);

        self::assertValid($response);
    }

    public function test_php_signed_rsa_sha512_is_accepted_by_wss4j(): void
    {
        $signed = Wsse::sign(signatureMethod: SignatureMethod::RSA_SHA512);

        $response = Oracle::post('/verify?sigalg=RSA_SHA512', $signed);

        self::assertValid($response);
    }

    public function test_php_signed_ecdsa_sha256_is_accepted_by_wss4j(): void
    {
        $signed = Wsse::sign(
            signatureMethod: SignatureMethod::ECDSA_SHA256,
            clientCertFile: Oracle::certPath('ec-client.pem'),
        );

        // The verifier resolves the EC signer from the BST the message carries; CA trust anchors the chain.
        $response = Oracle::post('/verify?sigalg=ECDSA_SHA256', $signed);

        self::assertValid($response);
    }

    /**
     * @return iterable<string, array{Outbound\KeyReference\KeyRef, string}>
     */
    public static function phpKeyRefProvider(): iterable
    {
        // keyref => verify keystore hint param. BST/SKI resolve from the recipients keystore (holds php-client);
        // IssuerSerial also resolves there because the php-client cert is present.
        yield 'BinarySecurityToken' => [Outbound\KeyReference\KeyRef::BinarySecurityToken, ''];
        yield 'SubjectKeyIdentifier' => [Outbound\KeyReference\KeyRef::SubjectKeyIdentifier, ''];
        yield 'IssuerSerial' => [Outbound\KeyReference\KeyRef::IssuerSerial, '?disableBsp=true'];
        // Thumbprint resolves from the recipients keystore too. This row exists because the PHP side once
        // emitted the KeyIdentifier in the WSS 1.1 namespace, which no conformant peer resolves: only a
        // PHP-outbound row catches that, since the PHP reader accepts either namespace on the way in.
        yield 'Thumbprint' => [Outbound\KeyReference\KeyRef::Thumbprint, ''];
    }

    #[DataProvider('phpKeyRefProvider')]
    public function test_php_signed_keyref_is_accepted_by_wss4j(Outbound\KeyReference\KeyRef $keyRef, string $query): void
    {
        $signed = Wsse::sign(keyRef: $keyRef);

        $response = Oracle::post('/verify' . $query, $signed);

        self::assertValid($response, 'WSS4J should verify a PHP signature referenced by ' . $keyRef->name);
    }

    // ----------------------------------------------------------------- positive: Java -> PHP

    public function test_wss4j_signed_happy_flow_is_accepted_by_php(): void
    {
        $javaSigned = Oracle::post('/sign', Oracle::sampleEnvelope())['body'];

        $this->phpVerify($javaSigned, [Part::body(), Part::timestamp()]);

        // phpVerify throws on failure; confirm the verified document is the real envelope, not an empty pass.
        self::assertStringContainsString('hello from the interop harness', $javaSigned);
    }

    /**
     * The default coverage requirement against a real peer. WSS4J signs the Body and the Timestamp and leaves
     * its own BinarySecurityToken unsigned, which is why the default stops at the Body: requiring the whole
     * Security header contents would refuse this message.
     */
    public function test_wss4j_signed_happy_flow_is_accepted_by_php_with_the_default_coverage(): void
    {
        $javaSigned = Oracle::post('/sign', Oracle::sampleEnvelope())['body'];

        $document = Document::fromXmlString($javaSigned);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());
        $trust = TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('ca.crt')));

        (new Inbound\VerifySignature($trust))($context);

        self::assertStringContainsString('hello from the interop harness', $javaSigned);
    }

    /**
     * The control for the row above: requiring the Security header contents refuses the same message, because
     * WSS4J does not sign its own BinarySecurityToken.
     */
    public function test_wss4j_signed_happy_flow_is_refused_when_the_header_contents_are_required(): void
    {
        $javaSigned = Oracle::post('/sign', Oracle::sampleEnvelope())['body'];

        self::assertPhpRejects(
            $javaSigned,
            [Part::body(), Part::securityHeaderContents()],
            TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('ca.crt'))),
        );
    }

    public function test_wss4j_signed_rsa_sha512_is_accepted_by_php(): void
    {
        $javaSigned = Oracle::post('/sign?sigalg=RSA_SHA512', Oracle::sampleEnvelope())['body'];

        $this->phpVerify($javaSigned, [Part::body(), Part::timestamp()]);
    }

    public function test_wss4j_signed_ecdsa_sha256_is_accepted_by_php(): void
    {
        $javaSigned = Oracle::post('/sign?sigalg=ECDSA_SHA256&sigalias=ec-client', Oracle::sampleEnvelope())['body'];

        $this->phpVerify($javaSigned, [Part::body(), Part::timestamp()]);
    }

    public function test_wss4j_signed_certificate_path_is_accepted_by_php(): void
    {
        // WSS4J's own path emitter (setUseSingleCertificate(false)), so the inbound half is validated against a
        // real peer's encoder rather than only against ours. It writes the order we write: the CA first, then
        // the java-server leaf.
        $javaSigned = Oracle::post('/sign?certpath=true', Oracle::sampleEnvelope())['body'];

        $this->phpVerify($javaSigned, [Part::body(), Part::timestamp()]);

        self::assertStringContainsString('X509PKIPathv1', $javaSigned);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function javaKeyRefProvider(): iterable
    {
        yield 'BinarySecurityToken' => ['BinarySecurityToken'];
        yield 'SubjectKeyIdentifier' => ['SubjectKeyIdentifier'];
        yield 'IssuerSerial' => ['IssuerSerial'];
        yield 'Thumbprint' => ['Thumbprint'];
    }

    #[DataProvider('javaKeyRefProvider')]
    public function test_wss4j_signed_keyref_is_accepted_by_php(string $keyRef): void
    {
        $javaSigned = Oracle::post('/sign?keyref=' . $keyRef, Oracle::sampleEnvelope())['body'];

        // SKI/IssuerSerial carry no certificate, so the signer leaf must be in the trust store to resolve it.
        $this->phpVerify(
            $javaSigned,
            [Part::body(), Part::timestamp()],
            TrustStore::fromCertificates(
                Certificate::fromFile(Oracle::certPath('java-server.crt')),
                Certificate::fromFile(Oracle::certPath('ca.crt')),
            ),
        );
    }

    // ----------------------------------------------------------------- negative: must be rejected

    public function test_tampered_php_signed_message_is_rejected_by_wss4j(): void
    {
        $tampered = Wsse::flipBody(Wsse::sign());

        self::assertRejected(Oracle::post('/verify', $tampered), 'WSS4J must reject a tampered signed Body');
    }

    public function test_tampered_wss4j_signed_message_is_rejected_by_php(): void
    {
        $tampered = Wsse::flipBody(Oracle::post('/sign', Oracle::sampleEnvelope())['body']);

        self::assertPhpRejects($tampered, [Part::body(), Part::timestamp()]);
    }

    public function test_xsw_wrapped_php_signed_message_is_rejected_by_wss4j(): void
    {
        $wrapped = Wsse::wrapBody(Wsse::sign());

        self::assertRejected(Oracle::post('/verify', $wrapped), 'WSS4J must reject an XSW-wrapped message');
    }

    public function test_xsw_wrapped_wss4j_signed_message_is_rejected_by_php(): void
    {
        $wrapped = Wsse::wrapBody(Oracle::post('/sign', Oracle::sampleEnvelope())['body']);

        self::assertPhpRejects($wrapped, [Part::body(), Part::timestamp()]);
    }

    /**
     * Pinning the peer's own CA-issued certificate rather than its issuer. OpenSSL cannot build a path that
     * ends at a CA-issued certificate, so this only works because a store entry matching the presented
     * certificate is honoured directly.
     */
    public function test_wss4j_signed_message_is_accepted_by_php_against_a_pinned_leaf(): void
    {
        $javaSigned = Oracle::post('/sign', Oracle::sampleEnvelope())['body'];

        $this->phpVerify(
            $javaSigned,
            [Part::body(), Part::timestamp()],
            TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('java-server.crt'))),
        );
    }

    /**
     * The finding a pin exists for: ec-client is a different certificate the same CA issued, so anchoring the
     * CA accepts it as readily as the real peer. Pinning the peer's certificate is what tells them apart.
     */
    public function test_a_sibling_certificate_from_the_same_ca_is_refused_against_a_pinned_leaf(): void
    {
        $siblingSigned = Oracle::post('/sign?sigalg=ECDSA_SHA256&sigalias=ec-client', Oracle::sampleEnvelope())['body'];

        // Anchoring the CA accepts it: the certificate is validly issued, it is simply not the peer.
        $this->phpVerify(
            $siblingSigned,
            [Part::body(), Part::timestamp()],
            TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('ca.crt'))),
        );

        self::assertPhpRejects(
            $siblingSigned,
            [Part::body(), Part::timestamp()],
            TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('java-server.crt'))),
        );
    }

    /**
     * The same finding closed the other way, with the CA still anchored: the application names the identity it
     * expected and the sibling is refused.
     */
    public function test_a_sibling_certificate_is_refused_by_an_expected_signer_check(): void
    {
        $siblingSigned = Oracle::post('/sign?sigalg=ECDSA_SHA256&sigalias=ec-client', Oracle::sampleEnvelope())['body'];

        $document = Document::fromXmlString($siblingSigned);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());
        $block = (new Inbound\VerifySignature(
            TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('ca.crt'))),
            signed: [Part::body(), Part::timestamp()],
        ))->onTrustedSigner(static function (TrustedSigner $signer): void {
            if (!str_contains($signer->subjectDistinguishedName()->toString(), 'java-server')) {
                throw new \RuntimeException('not the expected peer');
            }
        });

        $this->expectException(SecurityFault::class);
        $block($context);
    }

    public function test_untrusted_php_signer_is_rejected_by_wss4j(): void
    {
        $signed = Wsse::sign(clientCertFile: Oracle::certPath('untrusted-client.pem'));

        self::assertRejected(Oracle::post('/verify', $signed), 'WSS4J must reject a signer outside the shared CA');
    }

    public function test_untrusted_signer_is_rejected_by_php(): void
    {
        // A signature from a leaf issued by a DIFFERENT CA. The oracle keystore holds only CA-chained keys, so
        // this hostile message is built PHP-side with the untrusted leaf; PHP, trusting only the shared CA,
        // must reject it.
        $signed = Wsse::sign(clientCertFile: Oracle::certPath('untrusted-client.pem'));

        self::assertPhpRejects(
            $signed,
            [Part::body(), Part::timestamp()],
            TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('ca.crt'))),
        );
    }

    public function test_short_ttl_php_timestamp_is_rejected_by_php_after_expiry(): void
    {
        // Sign with a 1s TTL, then validate against a clock 1 hour later: the stamp is stale and must be refused.
        $signed = Wsse::sign(timestampTtl: 1);

        $document = Document::fromXmlString($signed);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());
        $action = (new Inbound\ValidateTimestamp())->withClock(self::fixedClock('+1 hour'));

        $this->expectRejection(static fn () => $action($context), 'an expired timestamp must be rejected');
    }

    public function test_expired_wss4j_timestamp_is_rejected_by_php(): void
    {
        $javaSigned = Oracle::post('/sign', Oracle::sampleEnvelope())['body'];

        $document = Document::fromXmlString($javaSigned);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());
        // A clock far in the future makes any freshly-minted stamp stale.
        $action = (new Inbound\ValidateTimestamp())->withClock(self::fixedClock('2099-01-01T00:00:00Z'));

        $this->expectRejection(static fn () => $action($context), 'a stamp checked from 2099 must be stale');
    }

    public function test_future_dated_timestamp_is_rejected_by_php(): void
    {
        $document = Document::fromXmlString(self::timestampEnvelope('2999-01-01T00:00:00Z', '2999-01-01T00:05:00Z'));
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());

        $this->expectRejection(
            static fn () => (new Inbound\ValidateTimestamp())($context),
            'a year-2999 Created is not yet valid and must be rejected',
        );
    }

    public function test_selective_signed_message_rejected_when_required_part_is_unsigned(): void
    {
        // PHP signs ONLY the custom header + Timestamp, not the Body.
        $signed = Wsse::sign(
            parts: [Part::element('urn:php-soap:interop:app', 'Tracking'), Part::timestamp()],
            inputXml: Wsse::customHeaderEnvelope(),
        );

        $document = Document::fromXmlString($signed);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());
        $trust = TrustStore::fromCertificates(
            Certificate::fromFile(Oracle::certPath('php-client.pem')),
            Certificate::fromFile(Oracle::certPath('ca.crt')),
        );

        // Requiring the Body (which is NOT signed) must be rejected.
        $this->expectRejection(
            static fn () => (new Inbound\VerifySignature($trust, signed: [Part::body()]))($context),
            'requiring an unsigned Body must be rejected',
        );
    }

    public function test_selective_signed_message_accepted_when_only_signed_parts_required(): void
    {
        $signed = Wsse::sign(
            parts: [Part::element('urn:php-soap:interop:app', 'Tracking'), Part::timestamp()],
            inputXml: Wsse::customHeaderEnvelope(),
        );

        $document = Document::fromXmlString($signed);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());
        $trust = TrustStore::fromCertificates(
            Certificate::fromFile(Oracle::certPath('php-client.pem')),
            Certificate::fromFile(Oracle::certPath('ca.crt')),
        );

        // Requiring exactly the signed parts is accepted (control for the negative above).
        (new Inbound\VerifySignature($trust, signed: [
            Part::element('urn:php-soap:interop:app', 'Tracking'),
            Part::timestamp(),
        ]))($context);

        // VerifySignature throws on failure; confirm the accepted document is the real envelope.
        self::assertStringContainsString('hello from the interop harness', $signed);
    }

    public function test_duplicate_signature_is_rejected_by_php(): void
    {
        $tampered = Wsse::duplicateSignature(Wsse::sign());

        self::assertPhpRejects($tampered, [Part::body(), Part::timestamp()]);
    }

    public function test_garbage_binary_security_token_is_rejected_by_php(): void
    {
        $tampered = Wsse::corruptBinarySecurityToken(Wsse::sign());

        self::assertPhpRejects($tampered, [Part::body(), Part::timestamp()]);
    }

    public function test_doctype_bearing_message_is_rejected_at_the_parse_boundary(): void
    {
        $signed = Wsse::sign();
        $doctype = '<!DOCTYPE soap:Envelope [ <!ENTITY xxe "injected"> ]>';
        $withDoctype = preg_replace('/(\?>)/', '$1' . "\n" . $doctype, $signed, 1);

        $this->expectRejection(
            static fn () => Document::fromXmlString((string) $withDoctype, \VeeWee\Xml\Dom\Configurator\disallow_doctype()),
            'a DOCTYPE must be refused by the disallow_doctype loader',
            \VeeWee\Xml\Exception\DoctypeNotAllowedException::class,
        );
    }

    // ----------------------------------------------------------------- helpers

    private function phpVerify(string $xml, array $signed, ?TrustStore $trust = null): void
    {
        $document = Document::fromXmlString($xml);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());
        $trust ??= TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('ca.crt')));

        // Throws SecurityFault if not accepted; reaching the assertion is the pass.
        (new Inbound\VerifySignature($trust, signed: $signed))($context);

        self::assertTrue(true);
    }

    private static function assertPhpRejects(string $xml, array $signed, ?TrustStore $trust = null): void
    {
        $document = Document::fromXmlString($xml);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());
        $trust ??= TrustStore::fromCertificates(
            Certificate::fromFile(Oracle::certPath('php-client.pem')),
            Certificate::fromFile(Oracle::certPath('ca.crt')),
        );

        try {
            (new Inbound\VerifySignature($trust, signed: $signed))($context);
            self::fail('PHP accepted a message it must reject');
        } catch (SecurityFault) {
            self::assertTrue(true);
        }
    }

    private function expectRejection(callable $fn, string $message, string $exception = SecurityFault::class): void
    {
        try {
            $fn();
            self::fail($message . ' (no rejection raised)');
        } catch (\Throwable $e) {
            self::assertInstanceOf($exception, $e, $message);
        }
    }

    private static function assertValid(array $response, string $message = ''): void
    {
        self::assertSame(200, $response['status'], $message);
        $decoded = json_decode($response['body'], true, flags: JSON_THROW_ON_ERROR);
        self::assertTrue($decoded['valid'] ?? false, $message . ' :: ' . $response['body']);
    }

    private static function assertRejected(array $response, string $message): void
    {
        self::assertSame(200, $response['status'], 'a verification "no" is a normal 200');
        $decoded = json_decode($response['body'], true, flags: JSON_THROW_ON_ERROR);
        self::assertFalse($decoded['valid'], $message);
        // A non-empty reason proves the oracle ran a real rejection branch, not a silent valid:false.
        self::assertNotEmpty($decoded['reason'] ?? '', $message . ' (oracle must supply a rejection reason)');
    }

    private static function fixedClock(string $instant): Clock
    {
        $iso = str_starts_with($instant, '+') || str_starts_with($instant, '-')
            ? gmdate('Y-m-d\TH:i:s\Z', strtotime($instant))
            : $instant;

        return new class($iso) implements Clock {
            public function __construct(private string $instant)
            {
            }

            public function now(): Timestamp
            {
                return Timestamp::parse($this->instant, "yyyy-MM-dd'T'HH:mm:ss'Z'", Timezone::UTC);
            }
        };
    }

    private static function timestampEnvelope(string $created, string $expires): string
    {
        return <<<XML
        <?xml version="1.0" encoding="UTF-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
          <soap:Header>
            <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                           xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
              <wsu:Timestamp wsu:Id="ts-1">
                <wsu:Created>{$created}</wsu:Created>
                <wsu:Expires>{$expires}</wsu:Expires>
              </wsu:Timestamp>
            </wsse:Security>
          </soap:Header>
          <soap:Body><tns:Ping xmlns:tns="urn:php-soap:interop"><tns:message>hi</tns:message></tns:Ping></soap:Body>
        </soap:Envelope>
        XML;
    }
}
