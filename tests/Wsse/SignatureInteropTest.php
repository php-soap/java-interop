<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use VeeWee\Xml\Dom\Document;

/**
 * The signing/verification vertical slice, both directions, between the php-soap http-wsse-middleware
 * and the WSS4J oracle. Signed parts and algorithms mirror the interop matrix happy flow (Body +
 * Timestamp, RSA-SHA256, exclusive C14N, BST key reference).
 */
final class SignatureInteropTest extends InteropTestCase
{
    public function test_php_signed_message_is_accepted_by_wss4j(): void
    {
        $signed = $this->phpSign(Oracle::sampleEnvelope());

        $response = Oracle::post('/verify', $signed);

        self::assertSame(200, $response['status']);
        self::assertJsonStringEqualsJsonString('{"valid":true}', $response['body']);
    }

    public function test_tampered_php_signed_message_is_rejected_by_wss4j(): void
    {
        $signed = $this->phpSign(Oracle::sampleEnvelope());
        $tampered = $this->flipBody($signed);

        $response = Oracle::post('/verify', $tampered);

        self::assertSame(200, $response['status'], 'a verification "no" is a normal 200 result');
        $decoded = json_decode($response['body'], true, flags: JSON_THROW_ON_ERROR);
        self::assertFalse($decoded['valid'], 'WSS4J must reject a tampered signed Body');
        self::assertArrayHasKey('reason', $decoded);
    }

    public function test_wss4j_signed_message_is_accepted_by_php_verify_signature(): void
    {
        $javaSigned = Oracle::post('/sign', Oracle::sampleEnvelope())['body'];

        $document = Document::fromXmlString($javaSigned);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());
        $trustStore = TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('ca.crt')));

        // Throws a SecurityFault if the signature/coverage is not accepted; reaching the assert is the pass.
        (new Inbound\VerifySignature($trustStore, signed: [Part::body(), Part::timestamp()]))($context);

        self::assertStringContainsString('Signature', $document->toXmlString());
    }

    private function phpSign(string $xml): string
    {
        $document = Document::fromXmlString($xml);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());
        $clientCertificate = ClientCertificate::fromFile(Oracle::certPath('php-client.pem'));

        (new Outbound\Timestamp())($context);
        (new Outbound\Signature($clientCertificate, keyRef: Outbound\KeyRef::BinarySecurityToken))($context);

        return $document->toXmlString();
    }

    /** Mutate the signed Body text so the canonicalised digest no longer matches (pure DOM, no middleware). */
    private function flipBody(string $signedXml): string
    {
        $dom = new \DOMDocument();
        $dom->preserveWhiteSpace = true;
        $dom->formatOutput = false;
        $dom->loadXML($signedXml);

        $xpath = new \DOMXPath($dom);
        $xpath->registerNamespace('soap12', 'http://www.w3.org/2003/05/soap-envelope');
        $message = $xpath->query('//soap12:Body//*[local-name()="message"]/text()')->item(0);
        self::assertInstanceOf(\DOMText::class, $message, 'sample Body should carry a message text node');
        $message->nodeValue .= ' TAMPERED';

        return $dom->saveXML();
    }
}
