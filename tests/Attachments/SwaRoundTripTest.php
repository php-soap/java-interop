<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Attachments;

use Http\Discovery\Psr17FactoryDiscovery;
use Phpro\ResourceStream\Factory\FileStream;
use PHPUnit\Framework\Attributes\DataProvider;
use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Multipart\AttachmentType;
use Soap\Psr18AttachmentsMiddleware\Multipart\RequestBuilder;
use Soap\Psr18AttachmentsMiddleware\Multipart\ResponseBuilder;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorage;

/**
 * Attachment interop between psr18-attachments-middleware and the SAAJ-backed oracle /attach endpoint.
 *
 * Each direction is real: PHP emits a multipart that the Java SAAJ parser reads back (asserting count +
 * SHA-256), and Java emits a multipart that the PHP ResponseBuilder parses (asserting the round-tripped
 * bytes hash identically). Both SwA and MTOM are covered.
 */
final class SwaRoundTripTest extends InteropTestCase
{
    // ----------------------------------------------------------------- in-process baseline

    public function test_swa_emit_then_parse_round_trips_bytes_and_hash(): void
    {
        $payload = random_bytes(512);
        $expectedSha = hash('sha256', $payload);

        $built = $this->phpEmit(AttachmentType::Swa, [['att1', $payload, 'payload.bin']]);

        $contentType = $built->getHeaderLine('Content-Type');
        self::assertStringContainsString('multipart/related', $contentType);

        $hashes = $this->phpParseHashes((string) $built->getBody(), $contentType, AttachmentType::Swa);
        self::assertContains($expectedSha, $hashes, 'round-tripped attachment bytes must hash identically');
    }

    // ----------------------------------------------------------------- PHP -> Java (SAAJ parses)

    /**
     * @return iterable<string, array{AttachmentType, string}>
     */
    public static function typeProvider(): iterable
    {
        // type => receive protocol. PHP SwA roots are text/xml (SAAJ reads as soap11); MTOM is soap12/xop.
        yield 'SwA' => [AttachmentType::Swa, 'soap11'];
        yield 'MTOM' => [AttachmentType::Mtom, 'soap12'];
    }

    #[DataProvider('typeProvider')]
    public function test_php_emitted_attachment_is_parsed_by_the_java_oracle(AttachmentType $type, string $protocol): void
    {
        $payload = $this->ramp(4096);
        $expectedSha = hash('sha256', $payload);

        $built = $this->phpEmit($type, [['att1', $payload, 'payload.bin']]);

        $result = $this->javaReceive((string) $built->getBody(), $built->getHeaderLine('Content-Type'), $protocol);

        self::assertSame(1, $result['count'], 'SAAJ should see exactly one attachment');
        self::assertContains($expectedSha, $result['sha256'], 'SAAJ must round-trip the attachment bytes');
    }

    public function test_php_emitted_swa_with_two_attachments_is_parsed_by_the_java_oracle(): void
    {
        $first = $this->ramp(4096);
        $second = $this->ramp(2048);
        $secondSha = hash('sha256', $second);

        $built = $this->phpEmit(AttachmentType::Swa, [
            ['att1', $first, 'first.bin'],
            ['att2', $second, 'second.bin'],
        ]);

        $result = $this->javaReceive((string) $built->getBody(), $built->getHeaderLine('Content-Type'), 'soap11');

        self::assertSame(2, $result['count']);
        self::assertContains($secondSha, $result['sha256'], 'the second attachment must survive the round-trip');
    }

    public function test_php_emitted_swa_with_boundary_lookalike_bytes_is_parsed_by_the_java_oracle(): void
    {
        // A payload that contains MIME boundary-lookalike bytes must not confuse the parser.
        $payload = "--=_Part_boundary_lookalike--\r\nMIME-Version: 1.0\r\n\x00\xFF binary tail";
        $expectedSha = hash('sha256', $payload);

        $built = $this->phpEmit(AttachmentType::Swa, [['att1', $payload, 'tricky.bin']]);

        $result = $this->javaReceive((string) $built->getBody(), $built->getHeaderLine('Content-Type'), 'soap11');

        self::assertSame(1, $result['count']);
        self::assertContains($expectedSha, $result['sha256']);
    }

    public function test_php_emitted_swa_with_unicode_filename_is_parsed_by_the_java_oracle(): void
    {
        $payload = $this->ramp(1024);
        $expectedSha = hash('sha256', $payload);

        $built = $this->phpEmit(AttachmentType::Swa, [['att1', $payload, 'facture été €.bin', 'my attachment']]);

        $result = $this->javaReceive((string) $built->getBody(), $built->getHeaderLine('Content-Type'), 'soap11');

        self::assertSame(1, $result['count']);
        self::assertContains($expectedSha, $result['sha256']);
    }

    // ----------------------------------------------------------------- Java -> PHP (PHP parses)

    #[DataProvider('typeProvider')]
    public function test_java_emitted_attachment_is_parsed_by_php(AttachmentType $type, string $protocol): void
    {
        $payload = $this->ramp(4096);
        $expectedSha = hash('sha256', $payload);

        $emitType = $type === AttachmentType::Mtom ? 'mtom' : 'swa';
        $response = Oracle::postRaw(
            sprintf('/attach?op=emit&type=%s&protocol=%s&cid=att1', $emitType, $protocol),
            $payload,
            'application/octet-stream',
        );

        self::assertSame(200, $response['status']);
        self::assertStringContainsString('multipart/related', $response['contentType']);

        $hashes = $this->phpParseHashes($response['body'], $response['contentType'], $type);
        self::assertContains($expectedSha, $hashes, 'PHP must round-trip the Java-emitted attachment bytes');
    }

    // ----------------------------------------------------------------- self round-trip only (Java leg blocked)

    public function test_zero_length_swa_attachment_round_trips_in_php(): void
    {
        // A 0-byte attachment: the Java SAAJ 3.0.4 parser has a known zero-length-part bug, so this leg is
        // proven by a PHP self round-trip only (documented limitation, matching the original harness).
        $built = $this->phpEmit(AttachmentType::Swa, [['att1', '', 'empty.bin']]);

        $hashes = $this->phpParseHashes((string) $built->getBody(), $built->getHeaderLine('Content-Type'), AttachmentType::Swa);

        self::assertContains(hash('sha256', ''), $hashes, 'an empty attachment must round-trip through PHP');
    }

    // ----------------------------------------------------------------- helpers

    /**
     * @param list<array{0:string,1:string,2:string,3?:string}> $attachments [cid, bytes, filename, name?]
     */
    private function phpEmit(AttachmentType $type, array $attachments): \Psr\Http\Message\RequestInterface
    {
        $storage = new AttachmentStorage();
        $tempFiles = [];
        foreach ($attachments as $a) {
            $file = tempnam(sys_get_temp_dir(), 'interop-attach-');
            file_put_contents($file, $a[1]);
            $tempFiles[] = $file;
            $storage->requestAttachments()->add(Attachment::cid(
                $a[0],
                $a[3] ?? 'file',
                $a[2],
                FileStream::create($file, FileStream::READ_MODE),
                'application/octet-stream',
            ));
        }

        $soapXml = $type === AttachmentType::Mtom
            ? $this->mtomEnvelope($attachments[0][0])
            : Oracle::sampleEnvelope();

        $requestFactory = Psr17FactoryDiscovery::findRequestFactory();
        $streamFactory = Psr17FactoryDiscovery::findStreamFactory();

        $request = $requestFactory
            ->createRequest('POST', 'http://interop.test/service')
            ->withBody($streamFactory->createStream($soapXml))
            ->withHeader('Content-Type', 'text/xml; charset=UTF-8');

        $built = (RequestBuilder::default())($request, $storage, $type);

        // Materialise the body before the temp files vanish.
        $body = (string) $built->getBody();
        foreach ($tempFiles as $f) {
            @unlink($f);
        }

        return $built->withBody($streamFactory->createStream($body));
    }

    /**
     * @return list<string>
     */
    private function phpParseHashes(string $body, string $contentType, AttachmentType $type): array
    {
        $responseFactory = Psr17FactoryDiscovery::findResponseFactory();
        $streamFactory = Psr17FactoryDiscovery::findStreamFactory();

        $response = $responseFactory
            ->createResponse(200)
            ->withHeader('Content-Type', $contentType)
            ->withBody($streamFactory->createStream($body));

        $storage = new AttachmentStorage();
        (ResponseBuilder::default())($response, $storage, $type);

        $hashes = [];
        foreach ($storage->responseAttachments() as $attachment) {
            $hashes[] = hash('sha256', $attachment->content->rewind()->getContents());
        }

        return $hashes;
    }

    /**
     * @return array{count:int, sha256:list<string>, soap:string}
     */
    private function javaReceive(string $body, string $contentType, string $protocol): array
    {
        $response = Oracle::postRaw('/attach?op=receive&protocol=' . $protocol, $body, $contentType);
        self::assertSame(200, $response['status'], 'oracle /attach receive failed: ' . $response['body']);

        return json_decode($response['body'], true, flags: JSON_THROW_ON_ERROR);
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

    private function mtomEnvelope(string $cid): string
    {
        return <<<XML
        <?xml version="1.0" encoding="UTF-8"?>
        <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
            <soap:Body>
                <tns:Ping xmlns:tns="urn:php-soap:interop">
                    <tns:message>hello from the interop harness</tns:message>
                    <tns:data><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="cid:{$cid}"/></tns:data>
                </tns:Ping>
            </soap:Body>
        </soap:Envelope>
        XML;
    }
}
