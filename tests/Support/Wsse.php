<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Support;

use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use VeeWee\Xml\Dom\Document;

/**
 * Builders for PHP-side WS-Security messages used across the interop suite, plus pure-DOM tamper synthesis
 * for the negative tests. Each method drives the http-wsse-middleware Outbound blocks; the tamper methods
 * deliberately use raw DOM (no middleware) so the hostile message is constructed independently of the
 * verifier under test.
 */
final class Wsse
{
    /**
     * Sign the sample with the given knobs and return the signed XML.
     *
     * @param list<Part>|null $parts override the signed parts (default Body + Timestamp)
     */
    public static function sign(
        ?SoapVersion $soapVersion = null,
        Outbound\KeyRef $keyRef = Outbound\KeyRef::BinarySecurityToken,
        ?SignatureMethod $signatureMethod = null,
        ?SignatureCanonicalization $canonicalization = null,
        ?string $clientCertFile = null,
        ?array $parts = null,
        ?string $inputXml = null,
        int $timestampTtl = 300,
    ): string {
        $soapVersion ??= SoapVersion::Soap12;
        $document = Document::fromXmlString($inputXml ?? Oracle::sampleEnvelope());
        $context = new WsseContext($document, $soapVersion, new SecurityProfile());
        $clientCertificate = ClientCertificate::fromFile($clientCertFile ?? Oracle::certPath('php-client.pem'));

        (new Outbound\Timestamp($timestampTtl))($context);

        $signature = new Outbound\Signature($clientCertificate, keyRef: $keyRef);
        if ($signatureMethod !== null) {
            $signature = $signature->withSignatureMethod($signatureMethod);
        }
        if ($canonicalization !== null) {
            $signature = $signature->withCanonicalization($canonicalization);
        }
        if ($parts !== null) {
            $signature = $signature->withParts($parts);
        }
        $signature($context);

        return $document->toXmlString();
    }

    /** Encrypt the sample Body to the given recipient cert and return the encrypted XML. */
    public static function encrypt(
        string $recipientCertFile,
        Outbound\EncKeyRef $encKeyRef = Outbound\EncKeyRef::SubjectKeyIdentifier,
        ?\Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod $dataMethod = null,
        ?KeyTransportAlgorithm $keyTransport = null,
        ?string $inputXml = null,
    ): string {
        $document = Document::fromXmlString($inputXml ?? Oracle::sampleEnvelope());
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());

        $recipient = Certificate::fromFile($recipientCertFile);
        $encryption = new Outbound\Encryption($recipient, encKeyRef: $encKeyRef);
        if ($dataMethod !== null) {
            $encryption = $encryption->withDataEncryptionMethod($dataMethod);
        }
        if ($keyTransport !== null) {
            $encryption = $encryption->withKeyTransportAlgorithm($keyTransport);
        }
        $encryption($context);

        return $document->toXmlString();
    }

    /** A SOAP 1.2 envelope carrying a custom app:Tracking header, for selective-signing tests. */
    public static function customHeaderEnvelope(): string
    {
        return <<<XML
        <?xml version="1.0" encoding="UTF-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
            <soap:Header>
                <app:Tracking xmlns:app="urn:php-soap:interop:app" wsu:Id="tracking-1"
                              xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                    <app:correlationId>abc-123</app:correlationId>
                </app:Tracking>
            </soap:Header>
            <soap:Body>
                <tns:Ping xmlns:tns="urn:php-soap:interop">
                    <tns:message>hello from the interop harness</tns:message>
                </tns:Ping>
            </soap:Body>
        </soap:Envelope>
        XML;
    }

    /** Flip the signed Body text so the canonicalised digest no longer matches (pure DOM tamper). */
    public static function flipBody(string $signedXml): string
    {
        $dom = self::loadDom($signedXml);
        $xpath = self::xpath($dom);
        $message = $xpath->query('//*[local-name()="Body"]//*[local-name()="message"]/text()')->item(0);
        if ($message instanceof \DOMText) {
            $message->nodeValue .= ' TAMPERED';
        } else {
            $body = $xpath->query('//*[local-name()="Body"]')->item(0);
            $body?->appendChild($dom->createTextNode('TAMPERED'));
        }

        return (string) $dom->saveXML();
    }

    /**
     * Classic XML Signature Wrapping: clone the signed Body into a wrapper, leave the original signed bytes
     * present so the signature still mathematically verifies, and replace the live Body with attacker content.
     * A verifier that ties the signed node to the consumed node by identity must reject this.
     */
    public static function wrapBody(string $signedXml): string
    {
        $dom = self::loadDom($signedXml);
        $xpath = self::xpath($dom);
        $body = $xpath->query('//*[local-name()="Body"]')->item(0);
        if (!$body instanceof \DOMElement) {
            return $signedXml;
        }

        $envelope = $dom->documentElement;
        $wrapper = $dom->createElementNS($envelope->namespaceURI, 'Wrapper');
        $wrapper->appendChild($body->cloneNode(true));
        $envelope->insertBefore($wrapper, $body);

        while ($body->firstChild) {
            $body->removeChild($body->firstChild);
        }
        $evil = $dom->createElementNS('urn:php-soap:interop', 'tns:Ping');
        $msg = $dom->createElementNS('urn:php-soap:interop', 'tns:message');
        $msg->appendChild($dom->createTextNode('attacker controlled payload'));
        $evil->appendChild($msg);
        $body->appendChild($evil);

        return (string) $dom->saveXML();
    }

    /** Add a second ds:Signature to wsse:Security (adversarial: a verifier must reject ambiguous signatures). */
    public static function duplicateSignature(string $signedXml): string
    {
        $dom = self::loadDom($signedXml);
        $xpath = self::xpath($dom);
        $sig = $xpath->query('//ds:Signature')->item(0);
        if ($sig instanceof \DOMElement) {
            $sig->parentNode?->appendChild($sig->cloneNode(true));
        }

        return (string) $dom->saveXML();
    }

    /** Replace the BST base64 with non-base64 garbage (malformed token probe). */
    public static function corruptBinarySecurityToken(string $signedXml): string
    {
        $dom = self::loadDom($signedXml);
        $xpath = self::xpath($dom);
        $bst = $xpath->query('//wsse:BinarySecurityToken')->item(0);
        if ($bst instanceof \DOMElement) {
            $bst->textContent = '!!!!not-base64!!!!';
        }

        return (string) $dom->saveXML();
    }

    private static function loadDom(string $xml): \DOMDocument
    {
        $dom = new \DOMDocument();
        $dom->preserveWhiteSpace = true;
        $dom->formatOutput = false;
        $dom->loadXML($xml);

        return $dom;
    }

    private static function xpath(\DOMDocument $dom): \DOMXPath
    {
        $xpath = new \DOMXPath($dom);
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $xpath->registerNamespace('wsse', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd');
        $xpath->registerNamespace('wsu', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
        $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');

        return $xpath;
    }
}
