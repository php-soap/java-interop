<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;
use SoapInterop\Tests\Support\Wsse;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use VeeWee\Xml\Dom\Document;

/**
 * Canonicalization interop. The default exclusive-C14N path is covered by SignatureInteropTest; this class
 * adds the inclusive Canonical XML 1.0 axis (REC-xml-c14n-20010315), which is opt-in on the PHP profile
 * (the default verifier accepts only the exclusive variants).
 */
final class CanonicalizationInteropTest extends InteropTestCase
{
    public function test_php_inclusive_c14n_signature_is_accepted_by_wss4j(): void
    {
        // PHP emits fully-inclusive C14N (REC-xml-c14n-20010315) on both ds:SignedInfo and every per-reference
        // Transform. disableBsp lets WSS4J accept the non-default reference transform alongside the BST keyref.
        $signed = Wsse::sign(canonicalization: SignatureCanonicalization::C14N);

        $response = Oracle::post('/verify?disableBsp=true', $signed);

        self::assertSame(200, $response['status']);
        self::assertJsonStringEqualsJsonString('{"valid":true}', $response['body']);
    }

    /**
     * The outbound half of the InclusiveNamespaces feature. A PHP round trip cannot prove this: our own reader
     * honours whatever PrefixList it is handed, so only a conformant peer re-canonicalizing from the
     * declaration can tell us the pinned list and the digests actually agree.
     */
    public function test_php_signature_pinning_inclusive_prefixes_is_accepted_by_wss4j(): void
    {
        $signed = Wsse::sign(inclusivePrefixes: true);

        self::assertStringContainsString('InclusiveNamespaces', $signed);
        self::assertStringContainsString('PrefixList=', $signed);

        $response = Oracle::post('/verify', $signed);

        self::assertSame(200, $response['status']);
        self::assertJsonStringEqualsJsonString('{"valid":true}', $response['body']);
    }

    public function test_wss4j_inclusive_c14n_signature_is_accepted_by_php(): void
    {
        $javaSigned = Oracle::post('/sign?c14n=INCLUSIVE&disableBsp=true', Oracle::sampleEnvelope())['body'];

        // The PHP verifier accepts inclusive canonicalization only when the profile opts in.
        $profile = new SecurityProfile(crypto: new CryptoPolicy(acceptedCanonicalizations: [
            SignatureCanonicalization::C14N,
            SignatureCanonicalization::C14N_COMMENTS,
            SignatureCanonicalization::EXC_C14N,
            SignatureCanonicalization::EXC_C14N_COMMENTS,
        ]));
        $document = Document::fromXmlString($javaSigned);
        $context = new WsseContext($document, SoapVersion::Soap12, $profile, new ExchangeKeys());
        $trust = TrustStore::fromCertificates(Certificate::fromFile(Oracle::certPath('ca.crt')));

        (new Inbound\VerifySignature($trust, signed: [Part::body(), Part::timestamp()]))($context);

        // VerifySignature throws on failure; confirm the verified document is the real envelope.
        self::assertStringContainsString('hello from the interop harness', $javaSigned);
    }
}
