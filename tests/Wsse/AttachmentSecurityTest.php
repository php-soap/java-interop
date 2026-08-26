<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use Http\Discovery\Psr17FactoryDiscovery;
use Phpro\ResourceStream\Factory\MemoryStream;
use Psl\MIME\Headers;
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
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\MimeHeaderBlock;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnsupportedAttachmentHeaderForm;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SigningFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;
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
    private const XOP = 'http://www.w3.org/2004/08/xop/include';

    // ---------------------------------------------------------------- PHP -> WSS4J

    #[DataProvider('packagings')]
    public function test_wss4j_verifies_an_attachment_php_signed(AttachmentType $type): void
    {
        $payload = $this->ramp(4096);

        $result = $this->javaCheck(
            $this->phpSecure($payload, sign: true, type: $type),
            signAttachments: true,
            type: $type,
        );

        self::assertTrue($result['valid'], 'WSS4J rejected a PHP-signed attachment: '.($result['error'] ?? ''));
        self::assertTrue($result['signature'], 'WSS4J saw no signature at all');
        self::assertContains(
            hash('sha256', $payload),
            $result['sha256'],
            'WSS4J must see the same octets PHP digested',
        );
    }

    #[DataProvider('packagings')]
    public function test_wss4j_decrypts_an_attachment_php_encrypted(AttachmentType $type): void
    {
        $payload = $this->ramp(4096);

        $result = $this->javaCheck(
            $this->phpSecure($payload, encrypt: true, type: $type),
            encryptAttachments: true,
            type: $type,
        );

        self::assertTrue($result['valid'], 'WSS4J rejected a PHP-encrypted attachment: '.($result['error'] ?? ''));
        self::assertTrue($result['encryption'], 'WSS4J saw no encryption at all');
        // The plaintext digest is the proof: a decryption that recovered nothing would also "not fail". Under
        // MTOM it is also the disclosure check. A peer that resolved the xop:Include before its security
        // interceptor ran would report the ciphertext it inlined, never this digest.
        self::assertContains(
            hash('sha256', $payload),
            $result['sha256'],
            'WSS4J must recover exactly the bytes PHP encrypted',
        );
        self::assertNotContains(
            hash('sha256', $payload),
            $result['rawSha256'],
            'the payload must reach WSS4J as ciphertext, never in the clear',
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

    #[DataProvider('packagings')]
    public function test_php_verifies_an_attachment_wss4j_signed(AttachmentType $type): void
    {
        $payload = $this->ramp(4096);

        [$document, $storage] = $this->javaSecured($payload, signAttachments: true, type: $type);

        (new Inbound\VerifySignature($this->trustStore(), signed: [Part::body()]))
            ->withAttachments(AttachmentParts::response($storage, ExternalPartCoverage::Content))(
                new WsseContext($document, self::soapVersionFor($type), new SecurityProfile()),
            );

        // Reaching here is the pass: the block throws rather than returning a verdict.
        self::assertSame(
            hash('sha256', $payload),
            hash('sha256', $this->onlyAttachment($storage)->content->rewind()->getContents()),
            'the attachment WSS4J signed must arrive unchanged',
        );
    }

    #[DataProvider('packagings')]
    public function test_php_decrypts_an_attachment_wss4j_encrypted(AttachmentType $type): void
    {
        $payload = $this->ramp(4096);

        [$document, $storage] = $this->javaSecured($payload, encryptAttachments: true, type: $type);

        // Arrived as ciphertext.
        self::assertNotSame(
            hash('sha256', $payload),
            hash('sha256', $this->onlyAttachment($storage)->content->rewind()->getContents()),
        );

        (new Inbound\Decrypt($this->privateKey()))
            ->withAttachments(AttachmentParts::response($storage, ExternalPartCoverage::Content))(
                new WsseContext($document, self::soapVersionFor($type), new SecurityProfile()),
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
            ->withAttachments(AttachmentParts::response($storage, ExternalPartCoverage::Content))(
                new WsseContext($document, SoapVersion::Soap11, new SecurityProfile()),
            );
    }

    // ---------------------------------------------------------------- the complete coverage

    #[DataProvider('packagings')]
    public function test_wss4j_verifies_an_attachment_php_covered_completely(AttachmentType $type): void
    {
        $payload = $this->ramp(4096);

        $result = $this->javaCheck(
            $this->phpSecure($payload, sign: true, type: $type, coverage: ExternalPartCoverage::Complete),
            signAttachments: true,
            type: $type,
            signCoverage: 'Element',
        );

        self::assertTrue(
            $result['valid'],
            'WSS4J rejected a completely covered attachment: '.($result['error'] ?? ''),
        );
        self::assertTrue($result['signature'], 'WSS4J saw no signature over the attachment');
    }

    /**
     * Differential test against the reference implementation, one header shape per row.
     *
     * The canonicalizer's rules were written from a reading of what WSS4J does, and a reading is what this
     * feature has already been caught out by once. Each row here is a rule stated as a claim and then
     * measured: WSS4J is handed the same part, and both the block it canonicalized and the digest it took
     * over that block have to agree with ours.
     *
     * The verification is the real assertion. The block comparison exists so a disagreement names itself
     * instead of surfacing as a bare digest failure.
     *
     * @param list<array{string, string}> $headers
     */
    #[DataProvider('headerShapes')]
    public function test_both_stacks_canonicalize_the_same_header_set_the_same_way(array $headers): void
    {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(Attachment::fromHeaders(
            Headers::fromPairs([['Content-ID', '<'.self::CID.'>'], ...$headers]),
            $this->stream($this->ramp(64)),
        ));

        $document = Document::fromXmlString(self::envelope());
        (new Outbound\Timestamp(300))($context = new WsseContext(
            $document,
            SoapVersion::Soap11,
            new SecurityProfile(),
        ));
        (new Outbound\Signature($this->clientCertificate()))
            ->withAttachments(AttachmentParts::request($storage, ExternalPartCoverage::Complete))($context);

        $result = $this->javaCheck(
            $this->pack($document->toXmlString(), $storage),
            signAttachments: true,
            signCoverage: 'Element',
        );

        $ours = (new MimeHeaderBlock())->canonicalize(
            $storage->requestAttachments()->findById('<'.self::CID.'>')->headers()
        );

        // The block comparison comes first and carries both forms, because a disagreement otherwise
        // surfaces as nothing more useful than "the signature was invalid".
        self::assertSame(
            [$ours],
            $result['headerBlocks'],
            "the two stacks canonicalized this header set differently.\n"
            ."ours:  ".var_export($ours, true)."\n"
            ."theirs: ".var_export($result['headerBlocks'], true)."\n",
        );
        self::assertTrue(
            $result['valid'],
            'WSS4J rejected a signature over this header set: '.($result['error'] ?? ''),
        );
        self::assertTrue($result['signature'], 'WSS4J saw no signature over the attachment');
    }

    /**
     * One row per canonicalization rule, so a rule that turns out to be a misreading fails on its own line.
     *
     * @return iterable<string, array{0: list<array{string, string}>}>
     */
    public static function headerShapes(): iterable
    {
        yield 'the set this package derives' => [[
            ['Content-Type', 'application/octet-stream'],
            ['Content-Disposition', 'attachment; name="invoice"; filename="invoice.pdf"'],
        ]];

        yield 'a media type with no parameters keeps its case' => [[
            ['Content-Type', 'APPLICATION/Octet-Stream'],
        ]];

        yield 'a parameterized media type is lowercased' => [[
            ['Content-Type', 'APPLICATION/Octet-Stream; CharSet=UTF-8'],
        ]];

        yield 'parameters are sorted' => [[
            ['Content-Type', 'application/octet-stream; zoom=3; alpha=1'],
        ]];

        yield 'bare parameter values are quoted' => [[
            ['Content-Type', 'application/octet-stream; version=1.7'],
        ]];

        yield 'quoted parameter values stay quoted once' => [[
            ['Content-Type', 'application/octet-stream; version="1.7"'],
        ]];

        yield 'a filename loses its case and a name does not' => [[
            ['Content-Type', 'application/octet-stream'],
            ['Content-Disposition', 'attachment; name="Invoice"; filename="Invoice.PDF"'],
        ]];

        yield 'leading whitespace is stripped' => [[
            ['Content-Type', "\t application/octet-stream"],
        ]];

        yield 'a Content-Location is considered' => [[
            ['Content-Type', 'application/octet-stream'],
            ['Content-Location', 'http://example.com/invoice.pdf'],
        ]];

        yield 'a header it does not consider is ignored' => [[
            ['Content-Type', 'application/octet-stream'],
            ['X-Whatever', 'ignored'],
        ]];

        yield 'every header it covers at once' => [[
            ['Content-Type', 'application/octet-stream; charset=UTF-8'],
            ['Content-Disposition', 'attachment; filename="Invoice.PDF"; name="Invoice"'],
            ['Content-Location', 'http://example.com/invoice.pdf'],
        ]];
    }


    #[DataProvider('packagings')]
    public function test_php_verifies_an_attachment_wss4j_covered_completely(AttachmentType $type): void
    {
        $payload = $this->ramp(4096);

        [$document, $storage] = $this->javaSecured(
            $payload,
            signAttachments: true,
            type: $type,
            signCoverage: 'Element',
        );

        (new Inbound\VerifySignature($this->trustStore(), signed: [Part::body()]))
            ->withAttachments(AttachmentParts::response($storage, ExternalPartCoverage::Complete))(
                new WsseContext($document, self::soapVersionFor($type), new SecurityProfile()),
            );

        self::assertSame(
            hash('sha256', $payload),
            hash('sha256', $this->onlyAttachment($storage)->content->rewind()->getContents()),
            'the attachment WSS4J covered must arrive unchanged',
        );
    }

    public function test_php_refuses_a_content_only_reference_when_it_asked_for_a_complete_one(): void
    {
        $payload = $this->ramp(1024);

        // A peer covering less than it was asked to. The digest would verify; the coverage is what refuses.
        [$document, $storage] = $this->javaSecured($payload, signAttachments: true);

        $this->expectException(SecurityFault::class);
        (new Inbound\VerifySignature($this->trustStore(), signed: [Part::body()]))
            ->withAttachments(AttachmentParts::response($storage, ExternalPartCoverage::Complete))(
                new WsseContext($document, SoapVersion::Soap11, new SecurityProfile()),
            );
    }

    public function test_php_decrypts_an_attachment_wss4j_encrypted_completely(): void
    {
        $payload = $this->ramp(4096);

        [$document, $storage] = $this->javaSecured(
            $payload,
            encryptAttachments: true,
            encryptCoverage: 'Element',
        );

        (new Inbound\Decrypt($this->privateKey()))
            ->withAttachments(AttachmentParts::response($storage, ExternalPartCoverage::Complete))(
                new WsseContext($document, SoapVersion::Soap11, new SecurityProfile()),
            );

        $opened = $this->onlyAttachment($storage);
        self::assertSame(
            hash('sha256', $payload),
            hash('sha256', $opened->content->rewind()->getContents()),
            'PHP must recover exactly the bytes WSS4J sealed',
        );
        // The metadata was inside the ciphertext, so recovering it is the whole point of this coverage.
        self::assertSame('<'.self::CID.'>', $opened->headers()->get('Content-ID'));
        self::assertNotNull($opened->headers()->get('Content-Type'));
    }

    public function test_wss4j_verifies_a_part_php_covered_completely_and_encrypted_content_only(): void
    {
        // The mixed mode the two policy validators actually reward, and the one whose failure looks like a
        // canonicalizer bug: the media type has to come back whole for the restored headers to canonicalize
        // to what was signed.
        $payload = $this->ramp(2048);

        $result = $this->javaCheck(
            $this->phpSecure($payload, sign: true, encrypt: true, coverage: ExternalPartCoverage::Complete),
            signAttachments: true,
            encryptAttachments: true,
            signCoverage: 'Element',
        );

        self::assertTrue($result['valid'], 'WSS4J rejected the mixed coverage: '.($result['error'] ?? ''));
        self::assertContains(hash('sha256', $payload), $result['sha256']);
    }

    public function test_php_refuses_to_cover_a_content_description(): void
    {
        // Measured, not read. This provider used to carry a Content-Description row and WSS4J answered
        // "the signature or decryption was invalid" for it: that header is the one of the five a peer
        // canonicalizes without stripping the whitespace a MIME parser leaves after the colon, so its
        // digest turns on whether the peer's own parser trimmed the separator. Refused rather than guessed.
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(Attachment::fromHeaders(
            Headers::fromPairs([
                ['Content-ID', '<'.self::CID.'>'],
                ['Content-Type', 'application/octet-stream'],
                ['Content-Description', 'an invoice'],
            ]),
            $this->stream($this->ramp(64)),
        ));

        $this->expectException(UnsupportedAttachmentHeaderForm::class);
        $this->expectExceptionMessage('"Content-Description" is the one header');

        (new Outbound\Signature($this->clientCertificate()))
            ->withAttachments(AttachmentParts::request($storage, ExternalPartCoverage::Complete))(
                new WsseContext(Document::fromXmlString(self::envelope()), SoapVersion::Soap11, new SecurityProfile()),
            );
    }

    public function test_php_refuses_to_cover_a_header_it_cannot_canonicalize(): void
    {
        // Pinned as deliberate rather than incidental. A guessed canonicalization is a wrong digest with no
        // diagnostic; a refusal names the header.
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(Attachment::fromHeaders(
            Headers::fromPairs([
                ['Content-ID', '<'.self::CID.'>'],
                ['Content-Type', 'application/octet-stream (the invoice)'],
            ]),
            $this->stream($this->ramp(64)),
        ));

        $this->expectException(UnsupportedAttachmentHeaderForm::class);
        $this->expectExceptionMessage('"Content-Type" carries a comment');

        (new Outbound\Signature($this->clientCertificate()))
            ->withAttachments(AttachmentParts::request($storage, ExternalPartCoverage::Complete))(
                new WsseContext(Document::fromXmlString(self::envelope()), SoapVersion::Soap11, new SecurityProfile()),
            );
    }

    // ---------------------------------------------------------------- the pinned refusals

    /**
     * @param non-empty-string $mimeType
     */
    #[DataProvider('canonicalizedMediaTypes')]
    public function test_php_refuses_to_sign_a_canonicalized_attachment(string $mimeType, string $reason): void
    {
        // Pinned rather than incidental. WSS4J's AttachmentContentSignatureTransform canonicalizes both
        // families before digesting, so signing one here would produce a digest it rejects. The companion
        // case below is the evidence for that claim rather than a reading of the profile.
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(new Attachment(
            '<'.self::CID.'>',
            'file',
            'note.txt',
            $mimeType,
            $this->stream("line one\nline two\n"),
        ));

        $document = Document::fromXmlString(self::envelope());

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage($reason);

        (new Outbound\Signature($this->clientCertificate()))
            ->withAttachments(AttachmentParts::request($storage, ExternalPartCoverage::Content))(
                new WsseContext($document, SoapVersion::Soap11, new SecurityProfile()),
            );
    }

    /**
     * @return iterable<string, array{0: non-empty-string, 1: string}>
     */
    public static function canonicalizedMediaTypes(): iterable
    {
        yield 'xml' => ['application/xml', 'XML canonicalization, which is not supported'];
        yield 'an xml suffix' => ['application/soap+xml', 'XML canonicalization, which is not supported'];
    }

    public function test_wss4j_digests_a_text_attachment_over_normalized_line_endings(): void
    {
        // The measurement the refusal above rests on, rather than a reading of the profile. WSS4J is asked to
        // sign a text part whose content mixes bare LFs with CRLFs, and the digest it publishes is read back
        // off the wire. It is the digest of the CRLF-normalized form, not of the octets that travelled.
        $payload = "line one\nline two\r\nline three";
        $normalized = "line one\r\nline two\r\nline three";

        [$document, $storage] = $this->javaSecured($payload, signAttachments: true, mimeType: 'text/plain');

        self::assertSame(
            $payload,
            $this->onlyAttachment($storage)->content->rewind()->getContents(),
            'the attachment travels unmodified; only the digest taken over it differs',
        );

        $published = $this->attachmentDigestOf($document);
        self::assertSame(
            base64_encode(hash('sha256', $normalized, true)),
            $published,
            'WSS4J must digest the CRLF-normalized form of a text part',
        );
        self::assertNotSame(
            base64_encode(hash('sha256', $payload, true)),
            $published,
            'and so must not digest the octets on the wire, which is what this package would sign',
        );
    }

    /** The ds:DigestValue of the ds:Reference covering the attachment. */
    private function attachmentDigestOf(Document $document): string
    {
        $digests = $document->xpath()->query(
            '//*[local-name()="Reference"][@URI="cid:'.self::CID.'"]/*[local-name()="DigestValue"]'
        );

        self::assertCount(1, $digests, 'expected exactly one signed reference over the attachment');

        return trim($digests->item(0)->textContent);
    }

    public function test_php_verifies_a_text_attachment_wss4j_signed_over_mixed_line_endings(): void
    {
        // The pair of the measurement above. WSS4J digests the normalized form; PHP now normalizes before
        // comparing, so a part whose two canonical forms differ is exactly the case that has to verify.
        $payload = "line one\nline two\r\nline three\rline four";

        [$document, $storage] = $this->javaSecured($payload, signAttachments: true, mimeType: 'text/plain');

        (new Inbound\VerifySignature($this->trustStore(), signed: [Part::body()]))
            ->withAttachments(AttachmentParts::response($storage, ExternalPartCoverage::Content))(
                new WsseContext($document, SoapVersion::Soap11, new SecurityProfile()),
            );

        self::assertSame(
            hash('sha256', $payload),
            hash('sha256', $this->onlyAttachment($storage)->content->rewind()->getContents()),
        );
    }

    public function test_wss4j_verifies_a_text_attachment_php_signed_over_mixed_line_endings(): void
    {
        // PHP composes the digest over the normalized form. WSS4J recomputes it its own way, so this is the
        // assertion that the two normalizations agree byte for byte rather than merely both existing.
        $payload = "line one\nline two\r\nline three\rline four";

        $result = $this->javaCheck(
            $this->phpSecure($payload, sign: true, mimeType: 'text/plain'),
            signAttachments: true,
        );

        self::assertTrue($result['valid'], 'WSS4J rejected a PHP-signed text attachment: '.($result['error'] ?? ''));
        self::assertContains(
            hash('sha256', $payload),
            $result['sha256'],
            'the octets must still travel unmodified; only the digest over them is normalized',
        );
    }

    /**
     * SwA and MTOM alike. Attachment security sees one mechanism in both, a MIME part addressed by a cid, and
     * no code on either side of the wire branches on the packaging. These cases are what says so.
     *
     * @return iterable<string, array{0: AttachmentType}>
     */
    public static function packagings(): iterable
    {
        yield 'swa' => [AttachmentType::Swa];
        yield 'mtom' => [AttachmentType::Mtom];
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
        AttachmentType $type = AttachmentType::Swa,
        string $mimeType = 'application/octet-stream',
        string $filename = 'invoice.pdf',
        ExternalPartCoverage $coverage = ExternalPartCoverage::Content,
    ): RequestInterface {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(new Attachment(
            '<'.self::CID.'>',
            'file',
            $filename,
            $mimeType,
            $this->stream($payload),
        ));

        $document = Document::fromXmlString(self::envelope($type));
        $context = new WsseContext($document, self::soapVersionFor($type), new SecurityProfile());

        (new Outbound\Timestamp(300))($context);

        if ($sign) {
            (new Outbound\Signature($this->clientCertificate()))
                ->withAttachments(AttachmentParts::request($storage, $coverage))($context);
        }

        if ($encrypt) {
            (new Outbound\Encryption($this->recipientCertificate()))
                ->withParts([])
                ->withAttachments(AttachmentParts::request($storage, ExternalPartCoverage::Content))($context);
        }

        if ($tamper) {
            $attachment = $this->onlyAttachment($storage, request: true);
            $bytes = $attachment->content->rewind()->getContents();
            $storage->requestAttachments()->replace($attachment->withContent(
                $this->stream(substr($bytes, 0, -1).chr(ord($bytes[-1]) ^ 0xff)),
                $attachment->mimeType,
            ));
        }

        return $this->pack($document->toXmlString(), $storage, $type);
    }

    /** Packs a SOAP part plus the storage's request attachments into a multipart request. */
    private function pack(
        string $soapXml,
        AttachmentStorage $storage,
        AttachmentType $type = AttachmentType::Swa,
    ): RequestInterface {
        $requestFactory = Psr17FactoryDiscovery::findRequestFactory();
        $streamFactory = Psr17FactoryDiscovery::findStreamFactory();

        $request = $requestFactory
            ->createRequest('POST', 'http://interop.test/service')
            ->withBody($streamFactory->createStream($soapXml))
            ->withHeader('Content-Type', match ($type) {
                AttachmentType::Swa => 'text/xml; charset=UTF-8',
                AttachmentType::Mtom => 'application/soap+xml; charset=UTF-8',
            });

        $built = (RequestBuilder::default())($request, $storage, $type);

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
        AttachmentType $type = AttachmentType::Swa,
        string $mimeType = 'application/octet-stream',
        string $signCoverage = 'Content',
        string $encryptCoverage = 'Content',
    ): array {
        $storage = new AttachmentStorage();
        $storage->requestAttachments()->add(new Attachment(
            '<'.self::CID.'>',
            'file',
            'invoice.pdf',
            $mimeType,
            $this->stream($payload),
        ));

        $request = $this->pack(self::envelope($type), $storage, $type);

        $response = Oracle::postRaw(
            sprintf(
                '/attach/secure?protocol=%s&signatt=%s&encatt=%s&signcover=%s&enccover=%s&recipient=php-client',
                self::protocolFor($type),
                $signAttachments ? 'true' : 'false',
                $encryptAttachments ? 'true' : 'false',
                $signCoverage,
                $encryptCoverage,
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
        $split = (ResponseBuilder::default())($psrResponse, $inbound, $type);

        return [Document::fromXmlString((string) $split->getBody()), $inbound];
    }

    /**
     * @return array{valid:bool, error:?string, signature:bool, encryption:bool, sha256:list<string>, rawSha256:list<string>, headerBlocks:list<string>}
     */
    private function javaCheck(
        RequestInterface $request,
        bool $signAttachments = false,
        bool $encryptAttachments = false,
        AttachmentType $type = AttachmentType::Swa,
        string $signCoverage = 'Content',
    ): array {
        $response = Oracle::postRaw(
            sprintf(
                '/attach/check?protocol=%s&signatt=%s&encatt=%s&signcover=%s',
                self::protocolFor($type),
                $signAttachments ? 'true' : 'false',
                $encryptAttachments ? 'true' : 'false',
                $signCoverage,
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
    private static function envelope(AttachmentType $type = AttachmentType::Swa): string
    {
        if ($type === AttachmentType::Swa) {
            return (string) file_get_contents(dirname(__DIR__, 2).'/samples/request-unsigned-soap11.xml');
        }

        // MTOM addresses the part from inside the document, while its bytes still travel as their own MIME
        // part. That is what makes the two packagings one mechanism as far as attachment security goes.
        return str_replace(
            '<tns:message>hello from the interop harness</tns:message>',
            '<tns:message><xop:Include xmlns:xop="'.self::XOP.'" href="cid:'.self::CID.'"/></tns:message>',
            (string) file_get_contents(dirname(__DIR__, 2).'/samples/request-unsigned.xml'),
        );
    }

    /**
     * SOAP 1.2 for MTOM, and not a preference. The attachments package writes start-info="application/soap+xml"
     * into an MTOM Content-Type whatever the envelope says, and SAAJ reads a start-info of text/xml as the only
     * SOAP 1.1 XOP package there is, so a 1.1 envelope in an MTOM package is one SAAJ refuses to parse at all.
     */
    private static function soapVersionFor(AttachmentType $type): SoapVersion
    {
        return $type === AttachmentType::Swa ? SoapVersion::Soap11 : SoapVersion::Soap12;
    }

    private static function protocolFor(AttachmentType $type): string
    {
        return $type === AttachmentType::Swa ? 'soap11' : 'soap12';
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
