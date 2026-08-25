<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use Http\Discovery\Psr17FactoryDiscovery;
use Phpro\ResourceStream\Factory\MemoryStream;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\RequestInterface;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Multipart\AttachmentType;
use Soap\Psr18AttachmentsMiddleware\Multipart\RequestBuilder;
use Soap\Psr18AttachmentsMiddleware\Multipart\ResponseBuilder;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorage;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SigningFailed;
use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use VeeWee\Xml\Dom\Document;

/**
 * WS-Security over SOAP attachments, cross-checked against Apache WSS4J in all four directions.
 *
 * These are the tests that actually matter for this feature. The digest and the ciphertext both cover the
 * attachment's raw octets, with no canonicalization and no transfer-encoding step, so any disagreement between
 * the two stacks about what those octets are surfaces as nothing more informative than a digest mismatch or a
 * failed tag. Only signing on one side and verifying on the other catches that.
 *
 * The oracle reports each attachment's SHA-256 *after* processing, which is what separates "WSS4J did not
 * complain" from "WSS4J recovered the bytes we sent".
 */
final class AttachmentSecurityTest extends InteropTestCase
{
    private const CID = 'invoice@example.com';

    // ---------------------------------------------------------------- PHP -> WSS4J

    public function test_wss4j_verifies_an_attachment_php_signed(): void
    {
        $payload = $this->ramp(4096);

        $result = $this->javaCheck($this->phpSecure($payload, sign: true), signAttachments: true);

        self::assertTrue($result['valid'], 'WSS4J rejected a PHP-signed attachment: '.($result['error'] ?? ''));
        self::assertTrue($result['signature'], 'WSS4J saw no signature at all');
        self::assertContains(
            hash('sha256', $payload),
            $result['sha256'],
            'WSS4J must see the same octets PHP digested',
        );
    }

    public function test_wss4j_decrypts_an_attachment_php_encrypted(): void
    {
        $payload = $this->ramp(4096);

        $result = $this->javaCheck($this->phpSecure($payload, encrypt: true), encryptAttachments: true);

        self::assertTrue($result['valid'], 'WSS4J rejected a PHP-encrypted attachment: '.($result['error'] ?? ''));
        self::assertTrue($result['encryption'], 'WSS4J saw no encryption at all');
        // The plaintext digest is the proof: a decryption that recovered nothing would also "not fail".
        self::assertContains(
            hash('sha256', $payload),
            $result['sha256'],
            'WSS4J must recover exactly the bytes PHP encrypted',
        );
    }

    public function test_wss4j_handles_a_php_signed_and_encrypted_attachment(): void
    {
        $payload = $this->ramp(2048);

        $result = $this->javaCheck(
            $this->phpSecure($payload, sign: true, encrypt: true),
            signAttachments: true,
            encryptAttachments: true,
        );

        self::assertTrue($result['valid'], 'WSS4J rejected sign-then-encrypt: '.($result['error'] ?? ''));
        self::assertContains(hash('sha256', $payload), $result['sha256']);
    }

    public function test_wss4j_rejects_a_php_signed_attachment_that_was_tampered_with(): void
    {
        $payload = $this->ramp(1024);

        // Flip one byte of the attachment after signing, leaving the XML untouched. Only the digest can catch
        // this, which is what makes it the test that the digest covers the bytes at all.
        $request = $this->phpSecure($payload, sign: true, tamper: true);
        $result = $this->javaCheck($request, signAttachments: true);

        self::assertFalse($result['valid'], 'WSS4J accepted a tampered attachment');
    }

    // ---------------------------------------------------------------- WSS4J -> PHP

    public function test_php_verifies_an_attachment_wss4j_signed(): void
    {
        $payload = $this->ramp(4096);

        [$document, $storage] = $this->javaSecured($payload, signAttachments: true);

        (new Inbound\VerifySignature($this->trustStore(), signed: [Part::body()]))
            ->withAttachments(AttachmentParts::response($storage))(
                new WsseContext($document, SoapVersion::Soap11, new SecurityProfile()),
            );

        // Reaching here is the pass: the block throws rather than returning a verdict.
        self::assertSame(
            hash('sha256', $payload),
            hash('sha256', $this->onlyAttachment($storage)->content->rewind()->getContents()),
            'the attachment WSS4J signed must arrive unchanged',
        );
    }

    public function test_php_decrypts_an_attachment_wss4j_encrypted(): void
    {
        $payload = $this->ramp(4096);

        [$document, $storage] = $this->javaSecured($payload, encryptAttachments: true);

        // Arrived as ciphertext.
        self::assertNotSame(
            hash('sha256', $payload),
            hash('sha256', $this->onlyAttachment($storage)->content->rewind()->getContents()),
        );

        (new Inbound\Decrypt($this->privateKey()))
            ->withAttachments(AttachmentParts::response($storage))(
                new WsseContext($document, SoapVersion::Soap11, new SecurityProfile()),
            );

        self::assertSame(
            hash('sha256', $payload),
            hash('sha256', $this->onlyAttachment($storage)->content->rewind()->getContents()),
            'PHP must recover exactly the bytes WSS4J encrypted',
        );
    }

    public function test_php_refuses_a_wss4j_signed_attachment_that_was_tampered_with(): void
    {
        $payload = $this->ramp(1024);

        [$document, $storage] = $this->javaSecured($payload, signAttachments: true);

        $attachment = $this->onlyAttachment($storage);
        $bytes = $attachment->content->rewind()->getContents();
        $storage->responseAttachments()->replace($attachment->withContent(
            $this->stream(substr($bytes, 0, -1).chr(ord($bytes[-1]) ^ 0xff)),
            $attachment->mimeType,
        ));

        $this->expectException(SecurityFault::class);
        (new Inbound\VerifySignature($this->trustStore(), signed: [Part::body()]))
            ->withAttachments(AttachmentParts::response($storage))(
                new WsseContext($document, SoapVersion::Soap11, new SecurityProfile()),
            );
    }

    // ---------------------------------------------------------------- the pinned refusal

    public function test_php_refuses_to_sign_a_text_attachment(): void
    {
        // Pinned rather than incidental: the profile canonicalizes line endings in text content before
        // digesting, which this package does not implement, so signing one would produce a digest WSS4J
        // rejects. Refusing at the point of signing is the deliberate behaviour.
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(new Attachment(
            '<'.self::CID.'>',
            'file',
            'note.txt',
            'text/plain',
            $this->stream("line one\nline two\n"),
        ));

        $document = Document::fromXmlString(self::envelope());

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage('content line-ending canonicalization, which is not supported');

        (new Outbound\Signature($this->clientCertificate()))
            ->withAttachments(AttachmentParts::request($storage))(
                new WsseContext($document, SoapVersion::Soap11, new SecurityProfile()),
            );
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Runs the PHP outbound blocks over a one-attachment message and packs the result into a multipart
     * request, exactly as the middleware stack would on a real call.
     */
    private function phpSecure(
        string $payload,
        bool $sign = false,
        bool $encrypt = false,
        bool $tamper = false,
    ): RequestInterface {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(new Attachment(
            '<'.self::CID.'>',
            'file',
            'invoice.pdf',
            'application/octet-stream',
            $this->stream($payload),
        ));

        $document = Document::fromXmlString(self::envelope());
        $context = new WsseContext($document, SoapVersion::Soap11, new SecurityProfile());

        (new Outbound\Timestamp(300))($context);

        if ($sign) {
            (new Outbound\Signature($this->clientCertificate()))
                ->withAttachments(AttachmentParts::request($storage))($context);
        }

        if ($encrypt) {
            (new Outbound\Encryption($this->recipientCertificate()))
                ->withParts([])
                ->withAttachments(AttachmentParts::request($storage))($context);
        }

        if ($tamper) {
            $attachment = $this->onlyAttachment($storage, request: true);
            $bytes = $attachment->content->rewind()->getContents();
            $storage->requestAttachments()->replace($attachment->withContent(
                $this->stream(substr($bytes, 0, -1).chr(ord($bytes[-1]) ^ 0xff)),
                $attachment->mimeType,
            ));
        }

        return $this->pack($document->toXmlString(), $storage);
    }

    /** Packs a SOAP part plus the storage's request attachments into a SwA multipart request. */
    private function pack(string $soapXml, AttachmentStorage $storage): RequestInterface
    {
        $requestFactory = Psr17FactoryDiscovery::findRequestFactory();
        $streamFactory = Psr17FactoryDiscovery::findStreamFactory();

        $request = $requestFactory
            ->createRequest('POST', 'http://interop.test/service')
            ->withBody($streamFactory->createStream($soapXml))
            ->withHeader('Content-Type', 'text/xml; charset=UTF-8');

        $built = (RequestBuilder::default())($request, $storage, AttachmentType::Swa);

        return $built->withBody($streamFactory->createStream((string) $built->getBody()));
    }

    /**
     * Asks the oracle to secure a plain multipart, then splits its response back out with the PHP response
     * builder, so the returned document and storage are what an inbound block would actually see.
     *
     * @return array{0: Document, 1: AttachmentStorage}
     */
    private function javaSecured(
        string $payload,
        bool $signAttachments = false,
        bool $encryptAttachments = false,
    ): array {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(new Attachment(
            '<'.self::CID.'>',
            'file',
            'invoice.pdf',
            'application/octet-stream',
            $this->stream($payload),
        ));

        $request = $this->pack(self::envelope(), $storage);

        $response = Oracle::postRaw(
            sprintf(
                '/attach/secure?protocol=soap11&signatt=%s&encatt=%s&recipient=php-client',
                $signAttachments ? 'true' : 'false',
                $encryptAttachments ? 'true' : 'false',
            ),
            (string) $request->getBody(),
            $request->getHeaderLine('Content-Type'),
        );

        self::assertSame(200, $response['status'], 'oracle /attach/secure failed: '.$response['body']);
        self::assertStringContainsString('multipart/related', $response['contentType']);

        $responseFactory = Psr17FactoryDiscovery::findResponseFactory();
        $streamFactory = Psr17FactoryDiscovery::findStreamFactory();

        $psrResponse = $responseFactory
            ->createResponse(200)
            ->withHeader('Content-Type', $response['contentType'])
            ->withBody($streamFactory->createStream($response['body']));

        $inbound = new AttachmentStorage();
        $split = (ResponseBuilder::default())($psrResponse, $inbound, AttachmentType::Swa);

        return [Document::fromXmlString((string) $split->getBody()), $inbound];
    }

    /**
     * @return array{valid:bool, error:?string, signature:bool, encryption:bool, sha256:list<string>}
     */
    private function javaCheck(
        RequestInterface $request,
        bool $signAttachments = false,
        bool $encryptAttachments = false,
    ): array {
        $response = Oracle::postRaw(
            sprintf(
                '/attach/check?protocol=soap11&signatt=%s&encatt=%s',
                $signAttachments ? 'true' : 'false',
                $encryptAttachments ? 'true' : 'false',
            ),
            (string) $request->getBody(),
            $request->getHeaderLine('Content-Type'),
        );

        self::assertSame(200, $response['status'], 'oracle /attach/check failed: '.$response['body']);

        return json_decode($response['body'], true, flags: JSON_THROW_ON_ERROR);
    }

    private function onlyAttachment(AttachmentStorage $storage, bool $request = false): Attachment
    {
        $collection = $request ? $storage->requestAttachments() : $storage->responseAttachments();
        self::assertCount(1, $collection, 'expected exactly one attachment');

        return $collection->findById('<'.self::CID.'>');
    }

    private function clientCertificate(): ClientCertificate
    {
        return ClientCertificate::fromFile(Oracle::certPath('php-client.pem'));
    }

    /**
     * java-server, because the oracle's single keystore holds only that private key. PHP encrypting to
     * php-client would produce a message WSS4J cannot open, which is a keystore fact rather than anything
     * about attachments.
     */
    private function recipientCertificate(): Certificate
    {
        return Certificate::fromFile(Oracle::certPath('java-server.crt'));
    }

    /** The other side of the same arrangement: the oracle encrypts to php-client, and this opens it. */
    private function privateKey(): Key
    {
        return Key::fromFile(Oracle::certPath('php-client.key'));
    }

    private function trustStore(): TrustStore
    {
        return TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('ca.crt')));
    }

    private function stream(string $contents): \Phpro\ResourceStream\ResourceStream
    {
        return MemoryStream::create()->write($contents)->rewind();
    }

    /**
     * SOAP 1.1, deliberately. SAAJ's 1.2 factory refuses a multipart whose Content-Type carries no
     * type="application/soap+xml" parameter, and the PHP RequestBuilder does not emit one, so the harness
     * reads a PHP SwA package as 1.1 throughout. Nothing about attachment security is version specific.
     */
    private static function envelope(): string
    {
        return (string) file_get_contents(dirname(__DIR__, 2).'/samples/request-unsigned-soap11.xml');
    }

    /** A deterministic byte ramp, so the SHA-256 is stable and the bytes are non-trivial. */
    private function ramp(int $length): string
    {
        $out = '';
        for ($i = 0; $i < $length; $i++) {
            $out .= chr($i % 256);
        }

        return $out;
    }
}
