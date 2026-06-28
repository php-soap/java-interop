<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Support;

use PHPUnit\Framework\TestCase;

/** Base case for interop tests: skips the whole class when the oracle is not reachable. */
abstract class InteropTestCase extends TestCase
{
    protected function setUp(): void
    {
        if (!Oracle::isUp()) {
            self::markTestSkipped('WSS4J oracle not reachable at ' . Oracle::baseUrl() . ' (set INTEROP_URL).');
        }
    }
}
