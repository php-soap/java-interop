<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use PHPUnit\Framework\Attributes\DataProvider;
use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use SoapInterop\Tests\Support\Wsse;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\OaepHash;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
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
     * @return iterable<string, array{string, string, list<DataEncryptionMethod>|null}>
     */
    public static function javaEncDataProvider(): iterable
    {
        // encdata param => oaep param => the ciphers the receiving policy accepts (null = secure defaults)
        yield 'AES-256-GCM, OAEP-SHA1' => ['AES256_GCM', 'SHA1', null];
        yield 'AES-256-GCM, OAEP-SHA256' => ['AES256_GCM', 'SHA256', null];
        // CBC is not accepted by default: a peer that can only send it has to be named. This row is what proves
        // the opt-in reaches a real WSS4J-encrypted message rather than only our own.
        yield 'AES-256-CBC, OAEP-SHA1, opted in' => ['AES256_CBC', 'SHA1', [DataEncryptionMethod::AES256_CBC]];
    }

    /**
     * @param list<DataEncryptionMethod>|null $acceptedCiphers
     */
    #[DataProvider('javaEncDataProvider')]
    public function test_wss4j_encrypted_message_is_decrypted_by_php(string $encData, string $oaep, ?array $acceptedCiphers): void
    {
        $encrypted = Oracle::post(
            sprintf('/encrypt?encdata=%s&oaep=%s', $encData, $oaep),
            Oracle::sampleEnvelope(),
        )['body'];

        self::assertStringContainsString('EncryptedData', $encrypted);

        $document = Document::fromXmlString($encrypted);
        $profile = new SecurityProfile(crypto: new CryptoPolicy(acceptedDataEncryptionMethods: $acceptedCiphers));
        $context = new WsseContext($document, SoapVersion::Soap12, $profile, new ExchangeKeys());

        try {
            (new Inbound\Decrypt(Key::fromFile(Oracle::certPath('php-client.key'))))($context);
        } catch (SecurityFault $fault) {
            self::fail('PHP failed to decrypt a WSS4J ' . $encData . '/' . $oaep . ' message: ' . $fault->getMessage());
        }

        self::assertStringContainsString(self::PLAINTEXT_MARKER, $document->toXmlString());
    }

    /**
     * The control for the opted-in CBC row: under the secure defaults the very same WSS4J message is refused.
     */
    public function test_wss4j_cbc_encrypted_message_is_refused_under_the_default_policy(): void
    {
        $encrypted = Oracle::post('/encrypt?encdata=AES256_CBC&oaep=SHA1', Oracle::sampleEnvelope())['body'];

        $document = Document::fromXmlString($encrypted);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys());

        $this->expectException(SecurityFault::class);
        (new Inbound\Decrypt(Key::fromFile(Oracle::certPath('php-client.key'))))($context);
    }

    public function test_wss4j_encrypted_with_legacy_mgf1p_and_sha256_is_decrypted_by_php(): void
    {
        // rsa-oaep-mgf1p fixes the mask to MGF1-SHA1, but ds:DigestMethod still sets the OAEP label hash, so
        // WSS4J emits this URI with a SHA-256 digest and no MGF child. PHP used to require the digest to be
        // SHA-1 under this URI and so could not decrypt the message at all.
        $encrypted = Oracle::post('/encrypt?enckey=RSA_OAEP_MGF1P&oaep=SHA256', Oracle::sampleEnvelope())['body'];

        self::assertStringContainsString('rsa-oaep-mgf1p', $encrypted);
        self::assertStringContainsString('xmlenc#sha256', $encrypted);

        $document = Document::fromXmlString($encrypted);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys());

        try {
            (new Inbound\Decrypt(Key::fromFile(Oracle::certPath('php-client.key'))))($context);
        } catch (SecurityFault $fault) {
            self::fail('PHP failed to decrypt a WSS4J mgf1p/SHA256 message: ' . $fault->getMessage());
        }

        self::assertStringContainsString(self::PLAINTEXT_MARKER, $document->toXmlString());
    }

    public function test_wss4j_encrypted_with_issuerserial_recipient_is_decrypted_by_php(): void
    {
        // Recipient resolved by IssuerSerial instead of SKI; PHP must still decrypt with its private key.
        $encrypted = Oracle::post('/encrypt?enckeyref=IssuerSerial', Oracle::sampleEnvelope())['body'];

        $document = Document::fromXmlString($encrypted);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys());
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
        yield 'AES-256-GCM, mgf1p with a SHA-1 label' => [DataEncryptionMethod::AES256_GCM, KeyTransportAlgorithm::legacyMgf1p()];
    }

    /**
     * The mirror of the inbound mgf1p row. That URI fixes the mask to MGF1-SHA1 while ds:DigestMethod still
     * sets the label hash, and a SHA-256 label under it is what WSS4J emits. Only a PHP-outbound row catches
     * getting the shape wrong: our own reader accepts either spelling, so a round trip stays green regardless.
     */
    public function test_php_encrypted_with_legacy_mgf1p_and_sha256_is_decrypted_by_wss4j(): void
    {
        $encrypted = Wsse::encrypt(
            recipientCertFile: Oracle::certPath('java-server.crt'),
            keyTransport: KeyTransportAlgorithm::fromMethod(KeyEncryptionMethod::RSA_OAEP_MGF1P, OaepHash::Sha256),
        );

        self::assertStringContainsString('rsa-oaep-mgf1p', $encrypted);
        self::assertStringContainsString('xmlenc#sha256', $encrypted);
        // The legacy URI takes no xenc11:MGF child at all; emitting one is what a strict peer refuses.
        self::assertStringNotContainsString('MGF', $encrypted);

        $response = Oracle::post('/decrypt', $encrypted);

        self::assertSame(200, $response['status'], 'oracle should decrypt mgf1p with a SHA-256 label: ' . $response['body']);
        self::assertStringContainsString(self::PLAINTEXT_MARKER, $response['body']);
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
            encKeyRef: Outbound\KeyReference\EncKeyRef::IssuerSerial,
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
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys());

        try {
            (new Inbound\Decrypt(Key::fromFile(Oracle::certPath('php-client.key'))))($context);
            self::fail('PHP must reject EncryptedData with a garbage CipherValue');
        } catch (SecurityFault) {
            self::assertTrue(true);
        }
    }
}
