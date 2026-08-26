<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use Http\Discovery\Psr17FactoryDiscovery;
use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use Psr\Http\Message\RequestInterface;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Multipart\AttachmentType;
use Soap\Psr18AttachmentsMiddleware\Multipart\RequestBuilder;
use Soap\Psr18AttachmentsMiddleware\Multipart\ResponseBuilder;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorage;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;
use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use VeeWee\Xml\Dom\Document;

/**
 * Cipher bytes travelling in MIME parts instead of base64 in the XML, cross-checked against Apache WSS4J.
 *
 * This is the shape a peer sends without either side agreeing to it. CXF turns storeBytesInAttachment on by
 * default whenever MTOM is enabled, and .NET and Metro do the same to any large encrypted content, which is
 * why Apache's own CXF-6409 exists: CXF could not read .NET messages for exactly this reason.
 *
 * A live peer is the only thing that settles it. The unit tests build the shape by hand, which proves the
 * reader but not the packaging, and the packaging is where the two stacks can disagree: which element the
 * pointer sits in, whether the part carries raw bytes or base64, and what its Content-ID looks like.
 */
final class OptimizedCipherBytesInteropTest extends InteropTestCase
{
    private const CID = 'invoice@example.com';
    private const MARKER = 'hello from the interop harness';

    // ---------------------------------------------------------------- WSS4J -> PHP

    public function test_php_decrypts_a_body_whose_cipher_bytes_wss4j_moved_into_parts(): void
    {
        [$document, $storage] = $this->javaOptimized();

        // The wire proof first: nothing was base64 in the document, or this test would pass without the
        // feature under test doing anything.
        self::assertStringContainsString('xop:Include', $document->toXmlString());
        self::assertStringNotContainsString(self::MARKER, $document->toXmlString());

        $this->resolveAndDecrypt($document, $storage);

        self::assertStringContainsString(self::MARKER, $document->toXmlString());
    }

    public function test_php_reads_a_binary_security_token_wss4j_moved_into_a_part(): void
    {
        // WSS4J moves the token's bytes out too, and expands them again itself whenever the token is signed.
        // So this arrives as a pointer in the token and a signature over the expanded form.
        [$document, $storage] = $this->javaOptimized(sign: true);

        (new Inbound\ResolveOptimizedBytes(
            AttachmentParts::response($storage, ExternalPartCoverage::Content),
        ))(new WsseContext($document, SoapVersion::Soap11, new SecurityProfile()));

        self::assertStringNotContainsString('xop:Include', $document->toXmlString());
    }

    public function test_php_refuses_the_same_message_without_the_block(): void
    {
        // The behaviour this feature changes. Fail-closed, and with nothing in the fault saying why.
        [$document] = $this->javaOptimized();

        $this->expectException(SecurityFault::class);
        (new Inbound\Decrypt($this->privateKey()))(
            new WsseContext($document, SoapVersion::Soap11, new SecurityProfile()),
        );
    }

    // ---------------------------------------------------------------- PHP -> WSS4J

    public function test_wss4j_decrypts_a_body_whose_cipher_bytes_php_moved_into_parts(): void
    {
        $request = $this->phpOptimized();

        self::assertStringNotContainsString(self::MARKER, (string) $request->getBody());

        $result = $this->javaCheck($request);

        self::assertTrue($result['valid'], 'WSS4J refused the message: '.(string) ($result['error'] ?? ''));
        self::assertStringContainsString(
            self::MARKER,
            $result['body'],
            'WSS4J must recover the body we encrypted, not merely accept the header',
        );
    }

    // ---------------------------------------------------------------- helpers

    /**
     * Asks the oracle for an encrypted message with storeBytesInAttachment on, and splits the multipart back
     * out the way an inbound pipeline would.
     *
     * One ordinary attachment travels along unsecured. It is there to prove the block leaves alone what it
     * has no business touching: the minted cipher parts are resolved, this one is not.
     *
     * @return array{0: Document, 1: AttachmentStorage}
     */
    private function javaOptimized(bool $sign = false): array
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(new Attachment(
            '<'.self::CID.'>',
            'file',
            'invoice.pdf',
            'application/octet-stream',
            $this->stream('%PDF-1.7 invoice bytes'),
        ));

        $request = $this->pack(
            (string) file_get_contents(dirname(__DIR__, 2).'/samples/request-unsigned-soap11.xml'),
            $storage,
        );

        $response = Oracle::postRaw(
            sprintf(
                '/attach/secure?protocol=soap11&storebytes=true&reqenc=true&sig=%s&recipient=php-client',
                $sign ? 'true' : 'false',
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

    private function resolveAndDecrypt(Document $document, AttachmentStorage $storage): void
    {
        $context = new WsseContext($document, SoapVersion::Soap11, new SecurityProfile());

        (new Inbound\ResolveOptimizedBytes(
            AttachmentParts::response($storage, ExternalPartCoverage::Content),
        ))($context);

        (new Inbound\Decrypt($this->privateKey()))($context);
    }

    /** Encrypts the Body with the cipher bytes going into minted parts, packed as the middleware would. */
    private function phpOptimized(): RequestInterface
    {
        $storage = new AttachmentStorage();
        $document = Document::fromXmlString(
            (string) file_get_contents(dirname(__DIR__, 2).'/samples/request-unsigned-soap11.xml'),
        );

        (new Outbound\Encryption($this->recipientCertificate()))
            ->withOptimizedCipherBytes(AttachmentParts::request($storage, ExternalPartCoverage::Content))(
                new WsseContext($document, SoapVersion::Soap11, new SecurityProfile()),
            );

        return $this->pack($document->toXmlString(), $storage);
    }

    /** Packs a SOAP part plus the storage's request attachments into a multipart request. */
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
     * @return array{valid:bool, error:?string, body:string}
     */
    private function javaCheck(RequestInterface $request): array
    {
        $response = Oracle::postRaw(
            '/attach/check?protocol=soap11&recipient=php-client',
            (string) $request->getBody(),
            $request->getHeaderLine('Content-Type'),
        );

        self::assertSame(200, $response['status'], 'oracle /attach/check failed: '.$response['body']);

        return json_decode($response['body'], true, flags: JSON_THROW_ON_ERROR);
    }

    /** The oracle encrypts to php-client, and this opens it. */
    private function privateKey(): Key
    {
        return Key::fromFile(Oracle::certPath('php-client.key'));
    }

    /** java-server, because the oracle's single keystore holds only that private key. */
    private function recipientCertificate(): Certificate
    {
        return Certificate::fromFile(Oracle::certPath('java-server.crt'));
    }

    private function stream(string $contents): ResourceStream
    {
        return MemoryStream::create()->write($contents)->rewind();
    }
}
