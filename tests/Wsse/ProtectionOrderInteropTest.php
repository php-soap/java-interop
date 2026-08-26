<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use VeeWee\Xml\Dom\Document;

/**
 * The order inbound blocks have to run in, against a real peer message rather than against our own reasoning.
 *
 * A peer that signs and then encrypts produces a signature over plaintext, so the receiver decrypts first and
 * verifies second. A peer that encrypts and then signs (sp:EncryptBeforeSigning) produces a signature over the
 * ciphertext, so the receiver has to verify first: decrypting replaces the very nodes the signature covers, and
 * a perfectly valid response then fails to verify.
 *
 * That is easy to state and easy to get backwards, and it was: the shipped import rule mandated one order for
 * every policy. These rows are what stops the rule drifting back, because both messages are produced by WSS4J
 * rather than by us, so the digests are computed over whichever bytes WSS4J actually signed.
 *
 * No new oracle capability is needed. Chaining /encrypt into /sign gives a signature over ciphertext, which is
 * exactly what encrypt-before-sign is.
 */
final class ProtectionOrderInteropTest extends InteropTestCase
{
    private const PLAINTEXT_MARKER = 'hello from the interop harness';

    public function test_encrypt_before_sign_verifies_first_then_decrypts(): void
    {
        $document = Document::fromXmlString($this->encryptedThenSigned());

        // Verify over the ciphertext, exactly as the peer signed it, before anything replaces those nodes.
        (new Inbound\VerifySignature($this->trustStore(), signed: [Part::body()]))($this->context($document));
        (new Inbound\Decrypt($this->privateKey()))($this->context($document));

        self::assertStringContainsString(self::PLAINTEXT_MARKER, $document->toXmlString());
    }

    public function test_decrypting_first_breaks_an_encrypt_before_sign_message(): void
    {
        // The control, and the reason the order is behaviour rather than style. The message is valid and the
        // signature is genuine; decrypting first swaps the signed EncryptedData for the recovered plaintext, so
        // the digest no longer matches anything in the document and a correct response is refused.
        $document = Document::fromXmlString($this->encryptedThenSigned());

        (new Inbound\Decrypt($this->privateKey()))($this->context($document));

        $this->expectException(SecurityFault::class);
        (new Inbound\VerifySignature($this->trustStore(), signed: [Part::body()]))($this->context($document));
    }

    public function test_sign_before_encrypt_still_decrypts_first_then_verifies(): void
    {
        // The common case, kept alongside so the two orders are pinned against each other rather than one
        // being asserted in isolation.
        $signedThenEncrypted = Oracle::post('/encrypt', Oracle::post('/sign', Oracle::sampleEnvelope())['body'])['body'];
        $document = Document::fromXmlString($signedThenEncrypted);

        (new Inbound\Decrypt($this->privateKey()))($this->context($document));
        (new Inbound\VerifySignature($this->trustStore(), signed: [Part::body()]))($this->context($document));

        self::assertStringContainsString(self::PLAINTEXT_MARKER, $document->toXmlString());
    }

    /**
     * WSS4J encrypts the Body, then signs the message it just produced, so the signature covers the ciphertext.
     */
    private function encryptedThenSigned(): string
    {
        $encrypted = Oracle::post('/encrypt', Oracle::sampleEnvelope())['body'];
        self::assertStringContainsString('EncryptedData', $encrypted);

        $signed = Oracle::post('/sign', $encrypted)['body'];
        self::assertStringContainsString('Signature', $signed);

        return $signed;
    }

    private function context(Document $document): WsseContext
    {
        return new WsseContext($document, SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys());
    }

    private function trustStore(): TrustStore
    {
        return TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('ca.crt')));
    }

    private function privateKey(): Key
    {
        return Key::fromFile(Oracle::certPath('php-client.key'));
    }
}
