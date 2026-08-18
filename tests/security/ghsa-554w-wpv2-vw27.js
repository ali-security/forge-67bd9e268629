/*
 * Regression Test for GHSA-554w-wpv2-vw27 (CVE-2025-66031)
 * Verifies that the parser enforces a maximum recursion depth
 * instead of crashing with a call stack overflow.
 */
'use strict';

var assert = require('assert');
var asn1 = require('../../lib/asn1');
var util = require('../../lib/util');

// Note: the regular expression is built with `new RegExp` so that it fits on
// a single line and is matched against `String(error)` on every supported
// version of node; the `{message: ...}` form of `assert.throws` is not
// available on older releases.
var MAX_DEPTH_EXCEEDED = new RegExp(
  '^Error: ASN\\.1 parsing error: Max depth exceeded\\.$');

describe('GHSA-554w-wpv2-vw27 Security Patch', function() {

  function createNestedDer(depth) {
    var obj = asn1.create(
      asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, '\x00');
    for(var i = 0; i < depth; ++i) {
      obj = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [obj]);
    }
    return asn1.toDer(obj).getBytes();
  }

  // encodes a DER definite length
  function derLength(length) {
    if(length < 0x80) {
      return String.fromCharCode(length);
    }
    var bytes = '';
    var value = length;
    while(value > 0) {
      bytes = String.fromCharCode(value & 0xff) + bytes;
      value = Math.floor(value / 256);
    }
    return String.fromCharCode(0x80 | bytes.length) + bytes;
  }

  // builds `depth` nested SEQUENCEs holding an INTEGER without recursing, so
  // that arbitrarily deep payloads can be created by the test itself
  function createNestedDerIteratively(depth) {
    var inner = String.fromCharCode(0x02, 0x01, 0x00);
    var length = inner.length;
    var headers = [];
    for(var i = 0; i < depth; ++i) {
      var header = String.fromCharCode(0x30) + derLength(length);
      headers.push(header);
      length += header.length;
    }
    headers.reverse();
    return headers.join('') + inner;
  }

  // wraps DER in a BIT STRING with zero unused bits; forge attempts to decode
  // such content as ASN.1, which is a second, encapsulated recursion path
  function wrapInBitString(der) {
    return String.fromCharCode(0x03) + derLength(der.length + 1) +
      String.fromCharCode(0x00) + der;
  }

  beforeEach(function() {
    // check max depth is the default
    assert.equal(asn1.maxDepth, 256);
  });

  it('should throw a manageable error when default recursion depth is ' +
    'exceeded', function() {
    // create a payload just above the default limit (256)
    var DANGEROUS_DEPTH = 257;
    var der = createNestedDer(DANGEROUS_DEPTH);
    var buf = util.createBuffer(der);

    // assert that it throws the correct error
    assert.throws(function() {
      asn1.fromDer(buf, {strict: true});
    }, MAX_DEPTH_EXCEEDED);
  });

  it('should throw a manageable error when optional recursion depth is ' +
    'exceeded', function() {
    // create a payload just above the optional defined limit (128)
    var DANGEROUS_DEPTH = 129;
    var der = createNestedDer(DANGEROUS_DEPTH);
    var buf = util.createBuffer(der);

    // assert that it throws the correct error
    assert.throws(function() {
      asn1.fromDer(buf, {strict: true, maxDepth: 128});
    }, MAX_DEPTH_EXCEEDED);
  });

  it('should not exhaust the call stack on a deeply nested payload',
    function() {
    // a payload deep enough to overflow the call stack of an unguarded parser
    var DANGEROUS_DEPTH = 50000;
    var der = createNestedDerIteratively(DANGEROUS_DEPTH);
    var buf = util.createBuffer(der);

    // a controlled error is thrown instead of a stack overflow
    assert.throws(function() {
      asn1.fromDer(buf, {strict: true});
    }, MAX_DEPTH_EXCEEDED);
  });

  it('should limit recursion into BIT STRING encapsulated content',
    function() {
    // deeply nested content hidden inside a BIT STRING must not be decoded
    // recursively past the depth limit
    var DANGEROUS_DEPTH = 1000;
    var der = wrapInBitString(createNestedDerIteratively(DANGEROUS_DEPTH));
    var buf = util.createBuffer(der);

    var obj = asn1.fromDer(buf, {strict: true});
    assert.equal(obj.type, asn1.Type.BITSTRING);
    // the content was left as raw bytes rather than parsed recursively
    assert.equal(typeof obj.value, 'string');
  });

  it('should limit recursion into BIT STRING encapsulated content with ' +
    'optional limits', function() {
    var DANGEROUS_DEPTH = 10;
    var der = wrapInBitString(createNestedDerIteratively(DANGEROUS_DEPTH));

    var obj = asn1.fromDer(util.createBuffer(der), {strict: true, maxDepth: 3});
    assert.equal(obj.type, asn1.Type.BITSTRING);
    // the content was left as raw bytes rather than parsed recursively
    assert.equal(typeof obj.value, 'string');
  });

  it('should still decode BIT STRING encapsulated content within limits',
    function() {
    var SAFE_DEPTH = 10;
    var der = wrapInBitString(createNestedDerIteratively(SAFE_DEPTH));

    var obj = asn1.fromDer(util.createBuffer(der), {strict: true});
    assert.equal(obj.type, asn1.Type.BITSTRING);
    // the encapsulated ASN.1 object was decoded as usual
    assert.equal(util.isArray(obj.value), true);
  });

  it('should still parse valid nested structures with new default limits',
    function() {
    var oldMaxDepth = asn1.maxDepth;
    asn1.maxDepth = 258;

    // create a payload just above the default limit (256)
    var DANGEROUS_DEPTH = 257;
    var der = createNestedDer(DANGEROUS_DEPTH);
    var buf = util.createBuffer(der);

    try {
      // verify with new default depth
      asn1.fromDer(buf, {strict: true});
    } finally {
      asn1.maxDepth = oldMaxDepth;
    }
  });

  it('should still parse valid nested structures within default limits',
    function() {
    // verify we didn't break default depth functionality
    var SAFE_DEPTH = 20;
    var der = createNestedDer(SAFE_DEPTH);
    var buf = util.createBuffer(der);

    asn1.fromDer(buf, {strict: true});
  });

  it('should still parse valid nested structures within optional limits',
    function() {
    // verify we didn't break optional depth functionality
    var SAFE_DEPTH = 20;
    var der = createNestedDer(SAFE_DEPTH);
    var buf = util.createBuffer(der);

    asn1.fromDer(buf, {strict: true, maxDepth: 128});
  });
});
