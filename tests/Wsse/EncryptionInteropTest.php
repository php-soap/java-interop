<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use PHPUnit\Framework\Attributes\DataProvider;
use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use SoapInterop\Tests\Support\Wsse;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use VeeWee\Xml\Dom\Document;

/**
 * Encryption interop between the http-wsse-middleware and the WSS4J oracle.
 *
 * Directional design (recipient determines who can decrypt):
 *  - Java /encrypt targets the php-client recipient cert, so PHP (holding php-client.key) decrypts it.
 *  - PHP encrypts to the java-server cert, so the oracle /decrypt (holding java-server.key) decrypts it.
 */
final class EncryptionInteropTest extends InteropTestCase
{
    private const PLAINTEXT_MARKER = 'hello from the interop harness';

    // ----------------------------------------------------------------- Java -> PHP

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function javaEncDataProvider(): iterable
    {
        // encdata param => oaep param
        yield 'AES-256-GCM, OAEP-SHA1' => ['AES256_GCM', 'SHA1'];
        yield 'AES-256-CBC, OAEP-SHA1' => ['AES256_CBC', 'SHA1'];
        yield 'AES-256-GCM, OAEP-SHA256' => ['AES256_GCM', 'SHA256'];
    }

    #[DataProvider('javaEncDataProvider')]
    public function test_wss4j_encrypted_message_is_decrypted_by_php(string $encData, string $oaep): void
    {
        $encrypted = Oracle::post(
            sprintf('/encrypt?encdata=%s&oaep=%s', $encData, $oaep),
            Oracle::sampleEnvelope(),
        )['body'];

        self::assertStringContainsString('EncryptedData', $encrypted);

        $document = Document::fromXmlString($encrypted);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());

        try {
            (new Inbound\Decrypt(Key::fromFile(Oracle::certPath('php-client.key'))))($context);
        } catch (SecurityFault $fault) {
            self::fail('PHP failed to decrypt a WSS4J ' . $encData . '/' . $oaep . ' message: ' . $fault->getMessage());
        }

        self::assertStringContainsString(self::PLAINTEXT_MARKER, $document->toXmlString());
    }

    public function test_wss4j_encrypted_with_issuerserial_recipient_is_decrypted_by_php(): void
    {
        // Recipient resolved by IssuerSerial instead of SKI; PHP must still decrypt with its private key.
        $encrypted = Oracle::post('/encrypt?enckeyref=IssuerSerial', Oracle::sampleEnvelope())['body'];

        $document = Document::fromXmlString($encrypted);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());
        (new Inbound\Decrypt(Key::fromFile(Oracle::certPath('php-client.key'))))($context);

        self::assertStringContainsString(self::PLAINTEXT_MARKER, $document->toXmlString());
    }

    // ----------------------------------------------------------------- PHP -> Java

    /**
     * @return iterable<string, array{DataEncryptionMethod, KeyTransportAlgorithm}>
     */
    public static function phpEncDataProvider(): iterable
    {
        yield 'AES-256-GCM, OAEP-SHA1' => [DataEncryptionMethod::AES256_GCM, KeyTransportAlgorithm::oaepSha1()];
        yield 'AES-256-CBC, OAEP-SHA1' => [DataEncryptionMethod::AES256_CBC, KeyTransportAlgorithm::oaepSha1()];
        yield 'AES-256-GCM, OAEP-SHA256' => [DataEncryptionMethod::AES256_GCM, KeyTransportAlgorithm::oaepSha256()];
    }

    #[DataProvider('phpEncDataProvider')]
    public function test_php_encrypted_message_is_decrypted_by_wss4j(
        DataEncryptionMethod $dataMethod,
        KeyTransportAlgorithm $keyTransport,
    ): void {
        $encrypted = Wsse::encrypt(
            recipientCertFile: Oracle::certPath('java-server.crt'),
            dataMethod: $dataMethod,
            keyTransport: $keyTransport,
        );

        self::assertStringContainsString('EncryptedData', $encrypted);

        $response = Oracle::post('/decrypt', $encrypted);

        self::assertSame(200, $response['status'], 'oracle should decrypt the PHP-encrypted message: ' . $response['body']);
        self::assertStringContainsString(self::PLAINTEXT_MARKER, $response['body']);
    }

    public function test_php_encrypted_with_issuerserial_recipient_is_decrypted_by_wss4j(): void
    {
        $encrypted = Wsse::encrypt(
            recipientCertFile: Oracle::certPath('java-server.crt'),
            encKeyRef: Outbound\EncKeyRef::IssuerSerial,
        );

        $response = Oracle::post('/decrypt', $encrypted);

        self::assertSame(200, $response['status'], $response['body']);
        self::assertStringContainsString(self::PLAINTEXT_MARKER, $response['body']);
    }

    // ----------------------------------------------------------------- negative

    public function test_garbage_ciphervalue_is_rejected_by_php(): void
    {
        $encrypted = Oracle::post('/encrypt', Oracle::sampleEnvelope())['body'];

        $dom = new \DOMDocument();
        $dom->loadXML($encrypted);
        $xpath = new \DOMXPath($dom);
        $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
        $cipherValues = $xpath->query('//xenc:EncryptedData//xenc:CipherValue');
        $node = $cipherValues->item($cipherValues->length - 1);
        self::assertInstanceOf(\DOMElement::class, $node);
        $node->textContent = base64_encode(random_bytes(48));

        $document = Document::fromXmlString((string) $dom->saveXML());
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());

        try {
            (new Inbound\Decrypt(Key::fromFile(Oracle::certPath('php-client.key'))))($context);
            self::fail('PHP must reject EncryptedData with a garbage CipherValue');
        } catch (SecurityFault) {
            self::assertTrue(true);
        }
    }
}
