<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use VeeWee\Xml\Dom\Document;

/**
 * UsernameToken interop. The PHP middleware emits a wsse:UsernameToken (PasswordText or PasswordDigest)
 * and WSS4J validates it. Only PHP -> Java is covered: the http-wsse-middleware has no inbound
 * UsernameToken validation block, so a Java -> PHP UsernameToken row is not portable (see README/matrix).
 */
final class UsernameTokenInteropTest extends InteropTestCase
{
    public function test_php_username_token_password_text_is_accepted_by_wss4j(): void
    {
        $message = $this->phpUsername(digest: false);

        $response = Oracle::post('/verify?ut=true&sig=false&ts=false&user=interop-user&pass=interop-secret', $message);

        self::assertValid($response, 'WSS4J should validate a PasswordText UsernameToken');
    }

    public function test_php_username_token_password_digest_is_accepted_by_wss4j(): void
    {
        $message = $this->phpUsername(digest: true);

        $response = Oracle::post('/verify?ut=true&sig=false&ts=false&user=interop-user&pass=interop-secret', $message);

        self::assertValid($response, 'WSS4J should validate a PasswordDigest UsernameToken');
    }

    private function phpUsername(bool $digest): string
    {
        $document = Document::fromXmlString(Oracle::sampleEnvelope());
        $context = new WsseContext($document, SoapVersion::Soap12, new SecurityProfile());

        (new Outbound\Username('interop-user', 'interop-secret', $digest))($context);

        return $document->toXmlString();
    }

    private static function assertValid(array $response, string $message): void
    {
        self::assertSame(200, $response['status'], $message . ' :: ' . $response['body']);
        $decoded = json_decode($response['body'], true, flags: JSON_THROW_ON_ERROR);
        self::assertTrue($decoded['valid'] ?? false, $message . ' :: ' . $response['body']);
    }
}
