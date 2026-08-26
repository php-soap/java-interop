<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Signing;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use VeeWee\Xml\Dom\Document;

/**
 * SAML Holder-of-Key interop, PHP -> Java only.
 *
 * Holder-of-Key means the signature was made with the key an assertion vouches for: the message carries the
 * assertion, and the signature's ds:KeyInfo points at it instead of at a certificate. What makes it worth
 * testing against a real peer is that the binding is invisible in the bytes -- a message with a decorative
 * reference looks identical to one where the key genuinely came from the assertion, and only a receiver that
 * resolves the key THROUGH the assertion can tell them apart. WSS4J does; our own round trip could not.
 *
 * The assertion is issued by the oracle rather than committed as a fixture, because it is bound to one public
 * key and the certificates are regenerated on every run. A frozen assertion would name a key that no longer
 * exists.
 *
 * Only this direction is covered. The reverse -- WSS4J emits a Holder-of-Key message and the PHP middleware
 * verifies it -- needs inbound SAML consumption, which this major deliberately does not implement.
 */
final class SamlHolderOfKeyInteropTest extends InteropTestCase
{
    public function test_php_holder_of_key_signature_is_accepted_by_wss4j(): void
    {
        $signed = $this->signWithAssertion($this->issuedAssertion());

        $response = Oracle::post('/verify?saml=true&samlhok=true', $signed);

        self::assertValid($response, 'WSS4J should resolve the signing key through the SAML assertion');
    }

    public function test_wss4j_refuses_an_assertion_vouching_for_a_different_key(): void
    {
        // The assertion is valid, signed, and confirms holder-of-key -- for someone else's key. The message is
        // signed with ours. If the reference were decorative this would pass, which is exactly what a decorative
        // implementation would ship and no round trip of our own would catch.
        $signed = $this->signWithAssertion($this->issuedAssertion(holder: 'java-server'));

        $response = Oracle::post('/verify?saml=true&samlhok=true', $signed);

        self::assertRejected($response, 'WSS4J must refuse a signature made with a key the assertion does not vouch for');
    }

    public function test_wss4j_refuses_an_unsigned_assertion(): void
    {
        // An unsigned assertion is a statement anybody could have written about a key they do not hold, so it
        // cannot vouch for anything. Accepting one would let a peer mint its own authorisation.
        $signed = $this->signWithAssertion($this->issuedAssertion(signed: false));

        $response = Oracle::post('/verify?saml=true&samlhok=true', $signed);

        self::assertRejected($response, 'WSS4J must refuse an unsigned Holder-of-Key assertion');
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

    /**
     * A Holder-of-Key assertion from the oracle standing in for an STS, bound to the current run's certificates.
     */
    private function issuedAssertion(string $holder = 'php-client', bool $signed = true): string
    {
        $query = '/saml/issue?samlholder=' . $holder . '&samlsign=' . ($signed ? 'true' : 'false');
        $response = Oracle::post($query, '');

        self::assertSame(200, $response['status'], 'the oracle should issue an assertion');

        return $response['body'];
    }

    /**
     * The documented Holder-of-Key composition: import the assertion, then sign referencing it. The Signature
     * block finds the assertion in the Security header the same way it finds a BinarySecurityToken, so nothing
     * has to carry the assertion id between the two blocks.
     */
    private function signWithAssertion(string $assertionXml): string
    {
        $document = Document::fromXmlString(Oracle::sampleEnvelope());
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys());
        $clientCertificate = ClientCertificate::fromFile(Oracle::certPath('php-client.pem'));

        (new Outbound\Timestamp(300))($context);
        (new Outbound\SamlAssertion($assertionXml, Outbound\SamlVersion::Saml20))($context);
        // Body and Timestamp explicitly, NOT the default Body + securityHeaderContents: that expands to every
        // child of the Security header, which here includes the assertion. Signing the assertion mints a
        // wsu:Id on it, and that attribute is inside what the issuer's own enveloped signature covers, so
        // stamping it invalidates the very assertion the reference depends on.
        (new Outbound\Signature(new Signing\Asymmetric(
            $clientCertificate,
            Outbound\KeyReference\KeyRef::SamlAssertion,
        )))
            ->withParts([Part::body(), Part::timestamp()])($context);

        return $document->toXmlString();
    }
}
