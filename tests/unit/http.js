var ASSERT = require('assert');
var HTTP = require('../../lib/http');

(function() {
  // the http client relies on the WHATWG URL parser, which is only available
  // as a global on newer platforms (browsers, node.js >= 10)
  var hasUrlParser = (typeof URL !== 'undefined');

  describe('http', function() {
    it('should not provide a url parser', function() {
      ASSERT.equal(typeof HTTP.parseUrl, 'undefined');
    });

    it('should match a cookie domain against the url host', function() {
      if(!hasUrlParser) {
        this.skip();
      }
      ASSERT.equal(
        HTTP.withinCookieDomain(
          'http://www.example.com/foo?bar=baz', '.example.com'),
        true);
      ASSERT.equal(
        HTTP.withinCookieDomain(
          'http://www.example.com/foo?bar=baz', '.other.com'),
        false);
    });

    it('should not read the url host from a fragment', function() {
      if(!hasUrlParser) {
        this.skip();
      }
      // the removed url parser allowed '#' in the host, so the host of this
      // url parsed as 'attacker.example.com#.victim.example.com', which made
      // an attacker controlled url appear to be within another domain
      ASSERT.equal(
        HTTP.withinCookieDomain(
          'http://attacker.example.com#.victim.example.com',
          '.victim.example.com'),
        false);
    });

    it('should not read the url host from a query string', function() {
      if(!hasUrlParser) {
        this.skip();
      }
      // as above, but using '?' instead of '#'
      ASSERT.equal(
        HTTP.withinCookieDomain(
          'http://attacker.example.com?.victim.example.com',
          '.victim.example.com'),
        false);
    });

    it('should not read the url host from user information', function() {
      if(!hasUrlParser) {
        this.skip();
      }
      // the removed url parser allowed '@' in the host, so the host of this
      // url parsed as 'victim.example.com@attacker.example.com' instead of
      // 'attacker.example.com'
      ASSERT.equal(
        HTTP.withinCookieDomain(
          'http://victim.example.com@attacker.example.com/',
          '.victim.example.com'),
        false);
      ASSERT.equal(
        HTTP.withinCookieDomain(
          'http://victim.example.com@attacker.example.com/',
          '.attacker.example.com'),
        true);
    });

    it('should not create a client for an invalid url', function() {
      if(!hasUrlParser) {
        this.skip();
      }
      ASSERT.throws(function() {
        HTTP.createClient({url: 'not a url'});
      }, /^Error: Invalid url\.$/);
    });
  });
})();
