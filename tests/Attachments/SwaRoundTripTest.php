<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Attachments;

use PHPUnit\Framework\TestCase;
use Http\Discovery\Psr17FactoryDiscovery;
use Phpro\ResourceStream\Factory\FileStream;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Multipart\AttachmentType;
use Soap\Psr18AttachmentsMiddleware\Multipart\RequestBuilder;
use Soap\Psr18AttachmentsMiddleware\Multipart\ResponseBuilder;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorage;

/**
 * Attachments interop suite.
 *
 * The first test is a real SwA emit -> parse round-trip through psr18-attachments-middleware: it proves
 * the suite wiring and the middleware's multipart emission/parsing agree on bytes and SHA-256. The
 * cross-stack leg against the WSS4J/SAAJ oracle is scaffolded as incomplete until the oracle grows
 * /attach endpoints (port of the CLI attachment-emit / attachment-receive ops).
 */
final class SwaRoundTripTest extends TestCase
{
    public function test_swa_emit_then_parse_round_trips_bytes_and_hash(): void
    {
        $soapXml = (string) file_get_contents(dirname(__DIR__, 2) . '/samples/request-unsigned.xml');
        $payload = random_bytes(512);
        $expectedSha = hash('sha256', $payload);

        $payloadFile = tempnam(sys_get_temp_dir(), 'interop-attach-');
        file_put_contents($payloadFile, $payload);

        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(Attachment::cid(
            'att1',
            'file',
            'payload.bin',
            FileStream::create($payloadFile, FileStream::READ_MODE),
            'application/octet-stream',
        ));

        $requestFactory = Psr17FactoryDiscovery::findRequestFactory();
        $streamFactory = Psr17FactoryDiscovery::findStreamFactory();

        $request = $requestFactory
            ->createRequest('POST', 'http://interop.test/service')
            ->withBody($streamFactory->createStream($soapXml))
            ->withHeader('Content-Type', 'text/xml; charset=UTF-8');

        $built = (RequestBuilder::default())($request, $storage, AttachmentType::Swa);

        $body = (string) $built->getBody();
        $contentType = $built->getHeaderLine('Content-Type');
        self::assertStringContainsString('multipart/related', $contentType);

        // Parse it straight back with the response builder.
        $responseFactory = Psr17FactoryDiscovery::findResponseFactory();
        $response = $responseFactory
            ->createResponse(200)
            ->withHeader('Content-Type', $contentType)
            ->withBody($streamFactory->createStream($body));

        $inStorage = new AttachmentStorage();
        $parsed = (ResponseBuilder::default())($response, $inStorage, AttachmentType::Swa);

        self::assertStringContainsString('hello from the interop harness', (string) $parsed->getBody());

        $hashes = [];
        foreach ($inStorage->responseAttachments() as $attachment) {
            $hashes[] = hash('sha256', $attachment->content->rewind()->getContents());
        }
        self::assertCount(1, $hashes);
        self::assertContains($expectedSha, $hashes, 'round-tripped attachment bytes must hash identically');

        @unlink($payloadFile);
    }

    public function test_php_emitted_swa_is_parsed_by_the_java_oracle(): void
    {
        self::markTestIncomplete(
            'Cross-stack attachments require /attach endpoints on the oracle (port of the CLI '
            . 'attachment-emit / attachment-receive SAAJ ops). Tracked as future work.',
        );
    }

    public function test_java_emitted_mtom_is_parsed_by_php(): void
    {
        self::markTestIncomplete(
            'Cross-stack MTOM requires the oracle /attach emit endpoint (SAAJ hand-built XOP package).',
        );
    }
}
