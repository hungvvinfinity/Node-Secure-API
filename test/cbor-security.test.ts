import test, { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SecurityError } from '../src/contracts.js';
import {
  scanCbor,
  validateAndDecodeCBOR,
  decodeMultipleBounded,
} from '../src/platform/cbor.js';

describe('CBOR Preflight Scanner & Decoder Security Invariants', () => {
  // Case 1: Positive control - Valid Map preserving distinct numeric and string keys
  it('preserves numeric vs string keys distinctly in Map without coercion', () => {
    // CBOR Map with 2 pairs:
    // Key 1 (uint 1: 0x01) => "apple" (text len 5: 0x65 'apple')
    // Key 2 (text "1": 0x61 '1') => "banana" (text len 6: 0x66 'banana')
    const cborMap = Buffer.from([
      0xa2, // map(2)
      0x01, // uint(1)
      0x65, 0x61, 0x70, 0x70, 0x6c, 0x65, // "apple"
      0x61, 0x31, // "1"
      0x66, 0x62, 0x61, 0x6e, 0x61, 0x6e, 0x61, // "banana"
    ]);

    const decoded = validateAndDecodeCBOR<Map<unknown, unknown>>(cborMap);
    assert.ok(decoded instanceof Map);
    assert.equal(decoded.size, 2);
    assert.equal(decoded.get(1), 'apple');
    assert.equal(decoded.get('1'), 'banana');
    assert.notEqual(decoded.get(1), decoded.get('1'));
  });

  // Case 2: Positive control - Valid byte string (signature/authData) returns Uint8Array/Buffer
  it('correctly decodes byte strings into raw byte buffers for cryptographic signatures', () => {
    // Map with key 1 => 4-byte byte string [0xde, 0xad, 0xbe, 0xef]
    const cborByteString = Buffer.from([
      0xa1, // map(1)
      0x01, // uint(1)
      0x44, 0xde, 0xad, 0xbe, 0xef, // bstr(4)
    ]);

    const decoded = validateAndDecodeCBOR<Map<unknown, Uint8Array>>(cborByteString);
    assert.ok(decoded instanceof Map);
    const bytes = decoded.get(1);
    assert.ok(bytes instanceof Uint8Array || Buffer.isBuffer(bytes));
    assert.deepEqual(Buffer.from(bytes), Buffer.from([0xde, 0xad, 0xbe, 0xef]));
  });

  // Case 3: Positive control - Sequential multi-item decoding with decodeMultipleBounded
  it('sequentially decodes multiple bounded items (e.g. COSE structure + trailing extension)', () => {
    // Item 1: Map { 1: 2 } => 0xa1, 0x01, 0x02
    // Item 2: Array [ "ok", 100 ] => 0x82, 0x62, 0x6f, 0x6b, 0x18, 0x64
    const multiItemBuffer = Buffer.from([
      0xa1, 0x01, 0x02,
      0x82, 0x62, 0x6f, 0x6b, 0x18, 0x64,
    ]);

    const scanResult = scanCbor(multiItemBuffer, { allowMultiple: true });
    assert.equal(scanResult.itemCount, 2);
    assert.equal(scanResult.bytesRead, multiItemBuffer.length);

    const decodedItems = decodeMultipleBounded(multiItemBuffer);
    assert.equal(decodedItems.length, 2);
    assert.ok(decodedItems[0] instanceof Map);
    assert.equal((decodedItems[0] as Map<unknown, unknown>).get(1), 2);
    assert.ok(Array.isArray(decodedItems[1]));
    assert.deepEqual(decodedItems[1], ['ok', 100]);
  });

  // Case 4: Rejects literal duplicate map keys
  it('rejects duplicate map keys with DUPLICATE_CBOR_KEY (400)', () => {
    // Map(2) with duplicate string key "id"
    const duplicateKeyMap = Buffer.from([
      0xa2, // map(2)
      0x62, 0x69, 0x64, 0x01, // "id": 1
      0x62, 0x69, 0x64, 0x02, // "id": 2
    ]);

    assert.throws(
      () => validateAndDecodeCBOR(duplicateKeyMap),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'DUPLICATE_CBOR_KEY');
        assert.equal(err.status, 400);
        return true;
      },
    );
  });

  // Case 5: Rejects semantic duplicate keys via overlong encoded text lengths
  it('rejects semantic duplicate keys encoded via different/overlong text lengths with DUPLICATE_CBOR_KEY (400)', () => {
    // Map(2) with two keys that decode to the same string "test":
    // Key 1: "test" encoded directly with length 4 (0x64, 't', 'e', 's', 't')
    // Key 2: "test" encoded with 1-byte length prefix (0x78, 0x04, 't', 'e', 's', 't')
    const semanticDuplicateMap = Buffer.from([
      0xa2, // map(2)
      0x64, 0x74, 0x65, 0x73, 0x74, // "test" (direct len 4)
      0x01, // 1
      0x78, 0x04, 0x74, 0x65, 0x73, 0x74, // "test" (overlong 1-byte len prefix 4)
      0x02, // 2
    ]);

    assert.throws(
      () => validateAndDecodeCBOR(semanticDuplicateMap),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'DUPLICATE_CBOR_KEY');
        assert.equal(err.status, 400);
        return true;
      },
    );
  });

  // Case 5: Rejects non-canonical / non-minimal integer encodings
  it('rejects non-minimal integer encodings with NON_CANONICAL_CBOR_INTEGER (400)', () => {
    // Value 5 encoded with 1-byte length prefix (0x18, 0x05) instead of direct 0x05
    const nonMinimal1 = Buffer.from([0x18, 0x05]);
    assert.throws(
      () => validateAndDecodeCBOR(nonMinimal1),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'NON_CANONICAL_CBOR_INTEGER');
        assert.equal(err.status, 400);
        return true;
      },
    );

    // Value 32 encoded with 2-byte length prefix (0x19, 0x00, 0x20) instead of 1-byte 0x18 0x20
    const nonMinimal2 = Buffer.from([0x19, 0x00, 0x20]);
    assert.throws(
      () => validateAndDecodeCBOR(nonMinimal2),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'NON_CANONICAL_CBOR_INTEGER');
        assert.equal(err.status, 400);
        return true;
      },
    );
  });

  // Case 6: Rejects unsupported CBOR tags (Major type 6)
  it('rejects CBOR semantic tags with UNSUPPORTED_CBOR_TAG (400)', () => {
    // Tag 1 (epoch timestamp): 0xc1 followed by uint 1 (0x01)
    const taggedCbor = Buffer.from([0xc1, 0x01]);
    assert.throws(
      () => validateAndDecodeCBOR(taggedCbor),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'UNSUPPORTED_CBOR_TAG');
        assert.equal(err.status, 400);
        return true;
      },
    );
  });

  // Case 7: Rejects indefinite-length encodings (additional info 31)
  it('rejects indefinite-length arrays, maps, and byte strings with INDEFINITE_LENGTH_CBOR (400)', () => {
    // Indefinite array: 0x9f, 0x01, 0xff (break)
    const indefArray = Buffer.from([0x9f, 0x01, 0xff]);
    assert.throws(
      () => validateAndDecodeCBOR(indefArray),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'INDEFINITE_LENGTH_CBOR');
        assert.equal(err.status, 400);
        return true;
      },
    );

    // Indefinite map: 0xbf, 0x01, 0x02, 0xff
    const indefMap = Buffer.from([0xbf, 0x01, 0x02, 0xff]);
    assert.throws(
      () => validateAndDecodeCBOR(indefMap),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'INDEFINITE_LENGTH_CBOR');
        return true;
      },
    );

    // Indefinite text string: 0x7f, 0x61, 0x61, 0xff
    const indefString = Buffer.from([0x7f, 0x61, 0x61, 0xff]);
    assert.throws(
      () => validateAndDecodeCBOR(indefString),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'INDEFINITE_LENGTH_CBOR');
        return true;
      },
    );
  });

  // Case 8: Rejects reserved additional information values 28..30
  it('rejects reserved additional information values 28..30 with INVALID_CBOR_PAYLOAD (400)', () => {
    for (const ai of [0x1c, 0x1d, 0x1e]) {
      const reservedBuffer = Buffer.from([ai]);
      assert.throws(
        () => validateAndDecodeCBOR(reservedBuffer),
        (err: unknown) => {
          assert.ok(err instanceof SecurityError);
          assert.equal(err.code, 'INVALID_CBOR_PAYLOAD');
          assert.equal(err.status, 400);
          return true;
        },
      );
    }
  });

  // Case 9: Rejects floating point numbers and unsupported simple values
  it('rejects floating-point numbers with UNSUPPORTED_CBOR_SIMPLE_VALUE (400)', () => {
    // 64-bit float (1.0): 0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    const float64 = Buffer.from([0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    assert.throws(
      () => validateAndDecodeCBOR(float64),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'UNSUPPORTED_CBOR_SIMPLE_VALUE');
        assert.equal(err.status, 400);
        return true;
      },
    );

    // 32-bit float (1.0): 0xfa, 0x3f, 0x80, 0x00, 0x00
    const float32 = Buffer.from([0xfa, 0x3f, 0x80, 0x00, 0x00]);
    assert.throws(
      () => validateAndDecodeCBOR(float32),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'UNSUPPORTED_CBOR_SIMPLE_VALUE');
        return true;
      },
    );
  });

  // Case 10: Rejects invalid UTF-8 sequences in text strings (Major 3)
  it('rejects non-UTF8 sequences in text strings with INVALID_CBOR_UTF8 (400)', () => {
    // 2-byte text string (0x62) containing invalid UTF-8 bytes [0xff, 0xff]
    const invalidUtf8 = Buffer.from([0x62, 0xff, 0xff]);
    assert.throws(
      () => validateAndDecodeCBOR(invalidUtf8),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'INVALID_CBOR_UTF8');
        assert.equal(err.status, 400);
        return true;
      },
    );
  });

  // Case 11: Rejects truncated payloads and partial lengths
  it('rejects truncated strings and incomplete buffers with TRUNCATED_CBOR_PAYLOAD (400)', () => {
    // Declares a 10-byte text string (0x6a) but only provides 3 bytes
    const truncatedText = Buffer.from([0x6a, 0x61, 0x62, 0x63]);
    assert.throws(
      () => validateAndDecodeCBOR(truncatedText),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'TRUNCATED_CBOR_PAYLOAD');
        assert.equal(err.status, 400);
        return true;
      },
    );

    // Declares 2-byte integer prefix (0x19) but provides only 1 byte
    const truncatedInt = Buffer.from([0x19, 0x01]);
    assert.throws(
      () => validateAndDecodeCBOR(truncatedInt),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'TRUNCATED_CBOR_PAYLOAD');
        return true;
      },
    );
  });

  // Case 12: Rejects deeply nested structures exceeding depth limit (>16)
  it('rejects recursive nesting exceeding depth limit with CBOR_DEPTH_EXCEEDED (400)', () => {
    // Construct 18 nested 1-element arrays: [ [ [ ... [0] ... ] ] ]
    const depth = 18;
    const nested = Buffer.alloc(depth + 1);
    for (let i = 0; i < depth; i++) {
      nested[i] = 0x81; // array(1)
    }
    nested[depth] = 0x00; // uint(0)

    assert.throws(
      () => validateAndDecodeCBOR(nested),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'CBOR_DEPTH_EXCEEDED');
        assert.equal(err.status, 400);
        return true;
      },
    );
  });

  // Case 13: Rejects excessive node count exceeding budget (>4096)
  it('rejects payload exceeding node count budget with CBOR_NODE_COUNT_EXCEEDED (400)', () => {
    // Construct array of 5000 small integers: 0x82 0x19 0x13 0x88 ...
    // Length: 5000 = 0x1388
    const count = 5000;
    const nodeBomb = Buffer.alloc(3 + count);
    nodeBomb[0] = 0x99; // array, 2-byte length
    nodeBomb[1] = (count >> 8) & 0xff;
    nodeBomb[2] = count & 0xff;
    for (let i = 3; i < 3 + count; i++) {
      nodeBomb[i] = 0x00; // uint(0)
    }

    assert.throws(
      () => validateAndDecodeCBOR(nodeBomb),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'CBOR_NODE_COUNT_EXCEEDED');
        assert.equal(err.status, 400);
        return true;
      },
    );
  });

  // Case 14: Rejects payload exceeding maxBytes constraint
  it('rejects payloads larger than maxBytes with CBOR_PAYLOAD_TOO_LARGE (400)', () => {
    const payload = Buffer.alloc(500, 0x00);
    assert.throws(
      () => scanCbor(payload, { maxBytes: 200 }),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'CBOR_PAYLOAD_TOO_LARGE');
        assert.equal(err.status, 400);
        return true;
      },
    );
  });

  // Case 15: Rejects trailing unparsed bytes in single-item validation
  it('rejects trailing data bytes with TRAILING_CBOR_BYTES (400)', () => {
    // Valid uint(1) followed by trailing garbage byte 0x99
    const trailingBytes = Buffer.from([0x01, 0x99]);
    assert.throws(
      () => validateAndDecodeCBOR(trailingBytes),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'TRAILING_CBOR_BYTES');
        assert.equal(err.status, 400);
        return true;
      },
    );
  });

  // Case 16: Rejects composite map keys (arrays or nested maps)
  it('rejects composite types as Map keys with UNSUPPORTED_CBOR_MAP_KEY (400)', () => {
    // Map with an array as key: { [1]: 2 } => 0xa1, 0x81, 0x01, 0x02
    const arrayAsKey = Buffer.from([0xa1, 0x81, 0x01, 0x02]);
    assert.throws(
      () => validateAndDecodeCBOR(arrayAsKey),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'UNSUPPORTED_CBOR_MAP_KEY');
        assert.equal(err.status, 400);
        return true;
      },
    );

    // Map with a nested map as key: { {}: 1 } => 0xa1, 0xa0, 0x01
    const mapAsKey = Buffer.from([0xa1, 0xa0, 0x01]);
    assert.throws(
      () => validateAndDecodeCBOR(mapAsKey),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'UNSUPPORTED_CBOR_MAP_KEY');
        return true;
      },
    );
  });

  // Case 17: Rejects empty payload and non-buffer input
  it('rejects empty payloads and non-buffer inputs with appropriate security codes', () => {
    assert.throws(
      () => validateAndDecodeCBOR(Buffer.alloc(0)),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'EMPTY_CBOR_PAYLOAD');
        return true;
      },
    );

    assert.throws(
      () => scanCbor('invalid-string' as unknown as Buffer),
      (err: unknown) => {
        assert.ok(err instanceof SecurityError);
        assert.equal(err.code, 'INVALID_CBOR_PAYLOAD');
        return true;
      },
    );
  });
});
