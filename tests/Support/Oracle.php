<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Support;

/**
 * Thin HTTP client for the WSS4J oracle plus path helpers for the shared cert material.
 *
 * The oracle base URL comes from INTEROP_URL (default http://127.0.0.1:8080); the cert directory from
 * INTEROP_CERTS (default certs/). All requests POST a raw SOAP/XML body and return the raw response.
 */
final class Oracle
{
    public static function baseUrl(): string
    {
        return rtrim(getenv('INTEROP_URL') ?: 'http://127.0.0.1:8080', '/');
    }

    public static function certsDir(): string
    {
        $dir = getenv('INTEROP_CERTS') ?: 'certs';
        if ($dir[0] !== '/') {
            $dir = dirname(__DIR__, 2) . '/' . $dir;
        }

        return rtrim($dir, '/');
    }

    public static function certPath(string $file): string
    {
        return self::certsDir() . '/' . $file;
    }

    public static function sampleEnvelope(): string
    {
        return (string) file_get_contents(dirname(__DIR__, 2) . '/samples/request-unsigned.xml');
    }

    /** True when the oracle answers GET /health with "ok". Used to skip when nothing is running. */
    public static function isUp(): bool
    {
        $response = @self::request('GET', '/health');

        return $response !== null && $response['status'] === 200 && trim($response['body']) === 'ok';
    }

    /** POST a body and return ['status' => int, 'body' => string]. */
    public static function post(string $path, string $body, string $contentType = 'text/xml; charset=UTF-8'): array
    {
        $response = self::request('POST', $path, $body, $contentType);
        if ($response === null) {
            throw new \RuntimeException('Oracle did not respond to POST ' . $path);
        }

        return $response;
    }

    /**
     * POST a raw (possibly binary) body and return the response Content-Type header alongside the body. The
     * attachment emit endpoint returns the multipart media type (with boundary) only in that header, so the
     * caller needs it to parse the multipart back.
     *
     * @return array{status:int, body:string, contentType:string}
     */
    public static function postRaw(string $path, string $body, string $contentType): array
    {
        $response = self::request('POST', $path, $body, $contentType, withResponseHeaders: true);
        if ($response === null) {
            throw new \RuntimeException('Oracle did not respond to POST ' . $path);
        }

        return $response;
    }

    /**
     * @return ($withResponseHeaders is true ? array{status:int, body:string, contentType:string}|null : array{status:int, body:string}|null)
     */
    private static function request(
        string $method,
        string $path,
        ?string $body = null,
        ?string $contentType = null,
        bool $withResponseHeaders = false,
    ): ?array {
        $ch = curl_init(self::baseUrl() . $path);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: ' . ($contentType ?? 'text/xml')]);
        }

        $responseContentType = '';
        if ($withResponseHeaders) {
            curl_setopt($ch, CURLOPT_HEADERFUNCTION, static function ($curl, string $header) use (&$responseContentType): int {
                if (stripos($header, 'content-type:') === 0) {
                    $responseContentType = trim(substr($header, strlen('content-type:')));
                }

                return strlen($header);
            });
        }

        $responseBody = curl_exec($ch);
        if ($responseBody === false) {
            curl_close($ch);

            return null;
        }
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($withResponseHeaders) {
            return ['status' => $status, 'body' => (string) $responseBody, 'contentType' => $responseContentType];
        }

        return ['status' => $status, 'body' => (string) $responseBody];
    }
}
