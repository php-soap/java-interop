<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
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
    public function test_wss4j_encrypted_message_is_decrypted_by_php(): void
    {
        // Default oracle encryption: AES-256-GCM data + RSA-OAEP key transport, recipient = php-client.
        $encrypted = Oracle::post('/encrypt', Oracle::sampleEnvelope())['body'];

        self::assertStringContainsString('EncryptedData', $encrypted);

        $document = Document::fromXmlString($encrypted);
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());
        $privateKey = Key::fromFile(Oracle::certPath('php-client.key'));

        try {
            (new Inbound\Decrypt($privateKey))($context);
        } catch (SecurityFault $fault) {
            self::fail('PHP failed to decrypt the WSS4J-encrypted message: ' . $fault->getMessage());
        }

        self::assertStringContainsString(
            'hello from the interop harness',
            $document->toXmlString(),
            'the recovered plaintext Body should be present after decryption',
        );
    }

    public function test_php_encrypted_message_is_decrypted_by_wss4j(): void
    {
        $document = Document::fromXmlString(Oracle::sampleEnvelope());
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());

        // Recipient = java-server, so the oracle's java-server private key can decrypt it.
        $recipient = Certificate::fromFile(Oracle::certPath('java-server.crt'));
        (new Outbound\Encryption($recipient, encKeyRef: Outbound\EncKeyRef::SubjectKeyIdentifier))($context);

        $encrypted = $document->toXmlString();
        self::assertStringContainsString('EncryptedData', $encrypted);

        $response = Oracle::post('/decrypt', $encrypted);

        self::assertSame(200, $response['status'], 'oracle should decrypt a PHP-encrypted message: ' . $response['body']);
        self::assertStringContainsString('hello from the interop harness', $response['body']);
    }
}
