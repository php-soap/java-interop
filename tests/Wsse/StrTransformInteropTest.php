<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use VeeWee\Xml\Dom\Document;

/**
 * The WS-Security STR-Transform, inbound only: a ds:Reference pointing at the
 * wsse:SecurityTokenReference in ds:KeyInfo, whose digest is taken over the wsse:BinarySecurityToken that
 * reference names. It is what covers a signing token by reference rather than directly.
 *
 * A PHP round trip cannot test any of this, because PHP never emits the transform: our own reader would only
 * be agreeing with our own fixtures about a shape we invented. Everything here therefore starts from bytes
 * WSS4J produced. That is not a theoretical concern: reading WSSecSignature is what revealed the reference
 * points into ds:KeyInfo rather than at a standalone reference in the header, which every hand-written
 * fixture had guessed wrong.
 */
final class StrTransformInteropTest extends InteropTestCase
{
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const STR_TRANSFORM = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform';

    public function test_wss4j_emits_the_transform_the_way_this_test_assumes(): void
    {
        // The premise every other row rests on. If WSS4J ever stops emitting this shape, these tests should
        // say so here rather than fail somewhere downstream looking like a PHP defect.
        $javaSigned = $this->strTransformSigned();

        self::assertStringContainsString(self::STR_TRANSFORM, $javaSigned);
        self::assertStringContainsString('TransformationParameters', $javaSigned);

        $document = Document::fromXmlString($javaSigned);
        $reference = $this->strTransformReferenceUri($document);

        // The reference names the wsse:SecurityTokenReference inside ds:KeyInfo, not a standalone one.
        $str = $this->elementById($document, $reference);
        self::assertSame('SecurityTokenReference', $str->localName);
        self::assertSame(self::WSSE, $str->namespaceURI);
        self::assertSame('KeyInfo', $str->parentElement?->localName);
    }

    public function test_wss4j_signed_token_covered_through_its_reference_is_accepted_by_php(): void
    {
        $javaSigned = $this->strTransformSigned();

        $this->phpVerify($javaSigned, [Part::body(), Part::timestamp()]);

        self::assertStringContainsString('hello from the interop harness', $javaSigned);
    }

    /**
     * The row that proves the dereference actually happened, and is the whole point of the feature.
     *
     * Part::securityHeaderContents() requires every token in the Security header to have been covered.
     * SignatureInteropTest pins that the same requirement refuses a default WSS4J message, because WSS4J
     * leaves its own BinarySecurityToken unsigned. Here the token is covered through its reference, so the
     * same requirement passes: PHP must be reporting the dereferenced token as signed rather than the
     * reference that named it.
     */
    public function test_php_can_require_the_security_header_contents_when_the_token_is_covered(): void
    {
        $javaSigned = $this->strTransformSigned();

        $this->phpVerify($javaSigned, [Part::body(), Part::timestamp(), Part::securityHeaderContents()]);

        self::assertStringContainsString('hello from the interop harness', $javaSigned);
    }

    /**
     * The control for the row above, against the same oracle in the same run: without the transform the token
     * is uncovered and the identical requirement is refused. Without this, a bug that reported everything as
     * signed would pass the row above and look like success.
     */
    public function test_php_still_refuses_the_header_contents_when_the_token_is_not_covered(): void
    {
        $javaSigned = Oracle::post('/sign', Oracle::sampleEnvelope())['body'];

        self::assertStringNotContainsString(self::STR_TRANSFORM, $javaSigned);
        $this->assertPhpRejects($javaSigned, [Part::body(), Part::securityHeaderContents()]);
    }

    /**
     * The other branch of the canonicalization rule, and the reason it is read from the output rather than
     * from the document. WSS4J adds an empty default-namespace declaration to the digest input when no
     * default namespace is in scope, and adds nothing when one is, so an envelope that declares one has to
     * verify too. Both branches are therefore evidence rather than one branch tested and the other argued.
     */
    public function test_wss4j_covered_token_verifies_when_the_envelope_declares_a_default_namespace(): void
    {
        $envelope = $this->envelopeWithDefaultNamespace();
        self::assertStringContainsString('xmlns="urn:php-soap:interop:default"', $envelope);

        $javaSigned = Oracle::post('/sign?strTransform=true', $envelope)['body'];

        $this->phpVerify($javaSigned, [Part::body(), Part::timestamp(), Part::securityHeaderContents()]);
    }

    /**
     * Tamper detection on the dereferenced element specifically. The digest covers the token, so mutating the
     * token's own bytes must break the signature. A verifier that digested the reference element instead
     * would accept this, which is exactly the bug this transform invites.
     */
    public function test_php_refuses_a_message_whose_covered_token_was_altered(): void
    {
        $javaSigned = $this->strTransformSigned();

        $tampered = $this->flipOneTokenByte($javaSigned);
        self::assertNotSame($javaSigned, $tampered);

        $this->assertPhpRejects($tampered, [Part::body(), Part::timestamp()]);
    }

    /**
     * The transform names its own canonicalization in wsse:TransformationParameters, and the profile's
     * allow-list gates it like any other reference's. WSS4J names exclusive C14N there, which the default
     * accepts; a profile that accepts no exclusive variant must refuse the same message, which proves the
     * inner method really is being read and gated rather than assumed.
     */
    public function test_the_transforms_own_canonicalization_is_gated_by_the_profile(): void
    {
        $javaSigned = $this->strTransformSigned();

        $document = Document::fromXmlString($javaSigned);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(
            crypto: new CryptoPolicy(acceptedCanonicalizations: [SignatureCanonicalization::C14N]),
        ),
            new ExchangeKeys()
        );

        try {
            (new Inbound\VerifySignature($this->trust(), signed: [Part::body()]))($context);
            self::fail('PHP accepted a canonicalization the profile does not allow');
        } catch (SecurityFault) {
            self::assertTrue(true);
        }
    }


    /**
     * The sample envelope with a default namespace declared on soap:Envelope, which the security header and
     * the token then inherit.
     */
    private function envelopeWithDefaultNamespace(): string
    {
        $envelope = Oracle::sampleEnvelope();
        $patched = preg_replace(
            '/(<(?:\\w+:)?Envelope\\b)/',
            '$1 xmlns="urn:php-soap:interop:default"',
            $envelope,
            1,
        );
        self::assertIsString($patched);
        self::assertNotSame($envelope, $patched);

        return $patched;
    }

    private function strTransformSigned(): string
    {
        return Oracle::post('/sign?strTransform=true', Oracle::sampleEnvelope())['body'];
    }

    private function phpVerify(string $xml, array $signed): void
    {
        $document = Document::fromXmlString($xml);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys());

        // Throws SecurityFault if not accepted; reaching the assertion is the pass.
        (new Inbound\VerifySignature($this->trust(), signed: $signed))($context);

        self::assertTrue(true);
    }

    private function assertPhpRejects(string $xml, array $signed): void
    {
        $document = Document::fromXmlString($xml);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys());

        try {
            (new Inbound\VerifySignature($this->trust(), signed: $signed))($context);
            self::fail('PHP accepted a message it must reject');
        } catch (SecurityFault) {
            self::assertTrue(true);
        }
    }

    private function trust(): TrustStore
    {
        return TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('ca.crt')));
    }

    /**
     * The URI of the one ds:Reference carrying the STR-Transform, without its '#'.
     */
    private function strTransformReferenceUri(Document $document): string
    {
        foreach ($document->toUnsafeDocument()->getElementsByTagName('*') as $element) {
            if ($element->localName !== 'Transform'
                || $element->getAttribute('Algorithm') !== self::STR_TRANSFORM
            ) {
                continue;
            }

            $reference = $element->parentElement?->parentElement;
            self::assertNotNull($reference);
            self::assertSame('Reference', $reference->localName);

            return ltrim((string) $reference->getAttribute('URI'), '#');
        }

        self::fail('WSS4J emitted no STR-Transform reference');
    }

    private function elementById(Document $document, string $id): \Dom\Element
    {
        foreach ($document->toUnsafeDocument()->getElementsByTagName('*') as $element) {
            foreach ($element->attributes as $attribute) {
                if ($attribute->localName === 'Id' && $attribute->value === $id) {
                    return $element;
                }
            }
        }

        self::fail(sprintf('No element carries the id "%s"', $id));
    }

    /**
     * Alters one byte of the base64 body of the wsse:BinarySecurityToken, leaving the document otherwise
     * identical, so only the dereferenced element's digest can notice.
     */
    private function flipOneTokenByte(string $xml): string
    {
        $document = Document::fromXmlString($xml);
        $tokens = $document->toUnsafeDocument()->getElementsByTagNameNS(self::WSSE, 'BinarySecurityToken');
        $token = $tokens->item(0);
        self::assertInstanceOf(\Dom\Element::class, $token);

        $body = trim((string) $token->textContent);
        self::assertGreaterThan(16, strlen($body));

        $flipped = $body;
        $flipped[10] = 'A' === $body[10] ? 'B' : 'A';
        $token->textContent = $flipped;

        return $document->toXmlString();
    }
}
