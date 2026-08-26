<?php

declare(strict_types=1);

namespace SoapInterop\Tests\Wsse;

use SoapInterop\Tests\Support\InteropTestCase;
use SoapInterop\Tests\Support\Oracle;

/**
 * The WS-SecurityPolicy SymmetricBinding wire shape, as Apache WSS4J emits and accepts it.
 *
 * This is the one test in the suite with no php-soap middleware in it, and deliberately so. The PHP symmetric
 * binding is not built yet, and the arrangement it is being built against has never been round-tripped by
 * anything here: an HMAC signature and an xenc:EncryptedData keyed by the same xenc:EncryptedKey, with the
 * xenc:ReferenceList a SIBLING of that key rather than a child of it, and a ds:KeyInfo on every
 * xenc:EncryptedData. Apache CXF and WCF are reported to emit exactly that; "reported to" is what this test
 * replaces. It pins down what WSS4J produces, so the PHP emitter has a shape to match, and it proves WSS4J's
 * reader accepts that shape, so the PHP emitter is worth writing at all.
 *
 * The sibling xenc:ReferenceList is the reason the shape matters. Nesting it inside the xenc:EncryptedKey, the
 * way a lone encryption block does, means the encryption block mutates a key element the signature may also
 * have to cover for token protection. As a sibling the two blocks never write to the same element, at the cost
 * of a ds:KeyInfo on each xenc:EncryptedData saying which key opens it.
 *
 * Both halves of every round trip here are WSS4J, which the rest of the suite avoids on purpose because our
 * own reader agreeing with our own writer proves nothing. Here it is the whole question: does one reference
 * implementation's reader accept its own writer's output in this arrangement. Once the PHP blocks exist they
 * replace one half of each round trip, and what stays behind is the reference shape.
 */
final class SymmetricBindingInteropTest extends InteropTestCase
{
    private const ENC_KEY_SHA1 =
        'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1';
    private const HMAC_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256';
    private const DERIVED_KEY_TOKEN = 'http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk';

    /** The recipient whose private key the oracle itself holds, so it can read back what it wrote. */
    private const RECIPIENT = 'java-server';

    // ------------------------------------------------------------------ the shared key

    public function test_one_encrypted_key_carries_the_key_for_both_blocks(): void
    {
        $xpath = $this->xpath($this->symmetric());

        self::assertCount(1, $xpath->query('//wsse:Security/xenc:EncryptedKey'));

        // Both blocks name the key the same way, which is what makes them the same key to a reader.
        $identifiers = $this->values(
            $xpath,
            '//wsse:SecurityTokenReference/wsse:KeyIdentifier[@ValueType="'.self::ENC_KEY_SHA1.'"]',
        );
        self::assertCount(2, $identifiers, 'the signature and the encryption each name the key once');
        self::assertSame($identifiers[0], $identifiers[1]);
    }

    public function test_the_shared_key_is_identified_by_the_digest_of_its_cipher_bytes(): void
    {
        $xpath = $this->xpath($this->symmetric());

        $cipherBytes = $this->value($xpath, '//xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue');
        $identifier = $this->value(
            $xpath,
            '//wsse:KeyIdentifier[@ValueType="'.self::ENC_KEY_SHA1.'"]',
        );

        // Not the digest of the session key itself, which the sender alone knows. Getting this wrong produces
        // an identifier a peer cannot compute, and a message it cannot resolve a key for.
        self::assertSame(
            base64_encode(sha1((string) base64_decode($cipherBytes, true), true)),
            $identifier,
        );
    }

    // ------------------------------------------------------------------ the sibling ReferenceList

    public function test_the_reference_list_is_a_sibling_of_the_encrypted_key_and_not_a_child(): void
    {
        $xpath = $this->xpath($this->symmetric());

        self::assertCount(1, $xpath->query('//wsse:Security/xenc:ReferenceList'));
        self::assertCount(0, $xpath->query('//xenc:EncryptedKey/xenc:ReferenceList'));
    }

    public function test_the_reference_list_follows_the_key_it_needs(): void
    {
        $xpath = $this->xpath($this->symmetric());

        // A reader that walks the header in document order has to meet the key before it is asked to open
        // anything with it, so this ordering is a correctness property and not cosmetics.
        self::assertSame(
            ['EncryptedKey', 'ReferenceList'],
            array_values(array_filter(
                $this->localNames($xpath, '//wsse:Security/*'),
                static fn (string $name): bool => in_array($name, ['EncryptedKey', 'ReferenceList'], true),
            )),
        );
    }

    public function test_every_encrypted_data_says_which_key_opens_it(): void
    {
        $xpath = $this->xpath($this->symmetric());

        $encryptedData = $xpath->query('//xenc:EncryptedData');
        self::assertGreaterThan(0, $encryptedData->count());
        foreach ($encryptedData as $element) {
            self::assertCount(
                1,
                $xpath->query('./ds:KeyInfo/wsse:SecurityTokenReference', $element),
                'a sibling ReferenceList leaves nothing else to say which key this was encrypted under',
            );
        }
    }

    // ------------------------------------------------------------------ the HMAC

    public function test_the_signature_is_an_hmac_and_nothing_certificate_shaped_signs(): void
    {
        $xpath = $this->xpath($this->symmetric());

        self::assertSame(self::HMAC_SHA256, $this->value($xpath, '//ds:SignedInfo/ds:SignatureMethod/@Algorithm'));
        self::assertCount(0, $xpath->query('//wsse:Security//wsse:BinarySecurityToken'));
        self::assertCount(0, $xpath->query('//ds:Signature//ds:X509Data'));
    }

    public function test_the_mac_is_never_truncated(): void
    {
        $xpath = $this->xpath($this->symmetric());

        // ds:HMACOutputLength is what turns a forgery from infeasible into a coin flip. This pins the emitted
        // shape only: it says the reference implementation never truncates, which is what PHP has to match. It
        // says nothing about what either reader does when handed one, and cannot, because adding the element to
        // a finished signature breaks the digest too and any refusal would be unattributable.
        self::assertCount(0, $xpath->query('//ds:HMACOutputLength'));
    }

    // ------------------------------------------------------------------ the round trip

    public function test_wss4j_accepts_the_symmetric_binding_it_emitted(): void
    {
        $result = $this->verify($this->symmetric());

        self::assertTrue($result['valid'], 'WSS4J refused its own symmetric binding: '.$result['reason']);
    }

    public function test_wss4j_refuses_the_same_message_with_a_forged_mac(): void
    {
        // The control. Without it a green round trip could mean the verifier never checked the HMAC at all,
        // because it silently failed to resolve a key and reported nothing.
        $result = $this->verify($this->forgeSignatureValue($this->symmetric()));

        self::assertFalse($result['valid']);
        self::assertNotSame('', $result['reason']);
    }

    // ------------------------------------------------------------------ RequireDerivedKeys

    public function test_each_block_derives_its_own_key_from_the_one_encrypted_key(): void
    {
        $xpath = $this->xpath($this->symmetric(derivedKeys: true));

        self::assertCount(1, $xpath->query('//wsse:Security/xenc:EncryptedKey'));

        $tokens = $xpath->query('//wsse:Security/wsc:DerivedKeyToken');
        self::assertCount(2, $tokens, 'one derived key for the signature, one for the encryption');

        $encryptedKeyId = $this->value($xpath, '//xenc:EncryptedKey/@Id');
        $nonces = [];
        foreach ($tokens as $token) {
            self::assertSame(
                '#'.$encryptedKeyId,
                $this->value($xpath, './wsse:SecurityTokenReference/wsse:Reference/@URI', $token),
                'both derived keys hang off the same xenc:EncryptedKey',
            );
            $nonces[] = $this->value($xpath, './wsc:Nonce', $token);
        }

        // Two blocks sharing a derived key would be one key doing two jobs, which is what deriving avoids.
        self::assertNotSame($nonces[0], $nonces[1]);
    }

    public function test_the_derived_blocks_reference_their_own_derived_key(): void
    {
        $xpath = $this->xpath($this->symmetric(derivedKeys: true));

        $referenced = $this->values(
            $xpath,
            '//wsse:SecurityTokenReference/wsse:Reference[@ValueType="'.self::DERIVED_KEY_TOKEN.'"]/@URI',
        );
        self::assertCount(2, $referenced);
        self::assertNotSame($referenced[0], $referenced[1]);

        $ids = array_map(
            static fn (string $uri): string => ltrim($uri, '#'),
            $referenced,
        );
        sort($ids);
        $tokenIds = $this->values($xpath, '//wsse:Security/wsc:DerivedKeyToken/@wsu:Id');
        sort($tokenIds);
        self::assertSame($tokenIds, $ids);
    }

    public function test_wss4j_accepts_the_derived_key_binding_it_emitted(): void
    {
        $result = $this->verify($this->symmetric(derivedKeys: true));

        self::assertTrue($result['valid'], 'WSS4J refused its own derived-key binding: '.$result['reason']);
    }

    // ------------------------------------------------------------------ helpers

    /** Asks the oracle for a symmetric-binding message, signed and encrypted under one session key. */
    private function symmetric(bool $derivedKeys = false): string
    {
        $response = Oracle::post(
            sprintf(
                '/sign?symmetric=true&sigalg=HMAC_SHA256&derivedkeys=%s&recipient=%s',
                $derivedKeys ? 'true' : 'false',
                self::RECIPIENT,
            ),
            Oracle::sampleEnvelope(),
        );

        self::assertSame(200, $response['status'], 'oracle /sign failed: '.$response['body']);

        return $response['body'];
    }

    /**
     * @return array{valid:bool, reason:string}
     */
    private function verify(string $xml): array
    {
        $response = Oracle::post('/verify?reqenc=true', $xml);

        self::assertSame(200, $response['status'], 'oracle /verify failed: '.$response['body']);

        $decoded = json_decode($response['body'], true, flags: JSON_THROW_ON_ERROR);

        return ['valid' => (bool) $decoded['valid'], 'reason' => (string) ($decoded['reason'] ?? '')];
    }

    /**
     * Flip the leading base64 character of the ds:SignatureValue, which always changes its first byte and so
     * always breaks the MAC, however the rest of the value happens to be padded.
     */
    private function forgeSignatureValue(string $xml): string
    {
        $xpath = $this->xpath($xml);
        $value = $xpath->query('//ds:SignatureValue')->item(0);
        self::assertInstanceOf(\DOMElement::class, $value);

        $encoded = $value->textContent;
        $value->textContent = ($encoded[0] === 'A' ? 'B' : 'A').substr($encoded, 1);

        return (string) $value->ownerDocument->saveXML();
    }

    private function xpath(string $xml): \DOMXPath
    {
        $dom = new \DOMDocument();
        $dom->preserveWhiteSpace = true;
        $dom->formatOutput = false;
        $dom->loadXML($xml);

        $xpath = new \DOMXPath($dom);
        $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $xpath->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
        $xpath->registerNamespace('wsse', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd');
        $xpath->registerNamespace('wsu', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
        $xpath->registerNamespace('wsc', 'http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512');

        return $xpath;
    }

    private function value(\DOMXPath $xpath, string $expression, ?\DOMNode $context = null): string
    {
        $node = $xpath->query($expression, $context)->item(0);
        self::assertNotNull($node, 'nothing matched '.$expression);

        return trim($node->nodeValue ?? '');
    }

    /**
     * @return list<string>
     */
    private function values(\DOMXPath $xpath, string $expression): array
    {
        $out = [];
        foreach ($xpath->query($expression) as $node) {
            $out[] = trim($node->nodeValue ?? '');
        }

        return $out;
    }

    /**
     * @return list<string>
     */
    private function localNames(\DOMXPath $xpath, string $expression): array
    {
        $out = [];
        foreach ($xpath->query($expression) as $node) {
            $out[] = $node->localName;
        }

        return $out;
    }
}
