(function() {
  var MAX_LENGTH, crypto, exports, url;
  var __hasProp = Object.prototype.hasOwnProperty;

  crypto = require('crypto');

  url = require('url');

  MAX_LENGTH = 4096;

  exports = module.exports = function(settings) {
    var k, s, v;
    s = {
      session_key: '_node',
      timeout: 24 * 60 * 60 * 1000,
      path: '/',
      domain: null,
      secure: false,
      useMaxAge: true,
      useExpires: true,
      useHttpOnly: true,
      onError: null
    };
    for (k in settings) {
      if (!__hasProp.call(settings, k)) continue;
      v = settings[k];
      s[k] = v;
    }
    if ("function" === typeof s.onError) exports.Events.onError = s.onError;
    if (!s.secret) {
      return exports.Events.throwErr('No secret set in cookie-session settings');
    }
    if ("string" !== typeof s.path || 0 !== s.path.indexOf("/")) {
      return exports.Events.throwErr('Invalid cookie path, must start with "/"');
    }
    return function(req, res, next) {
      var _writeHead;
      var _this = this;
      if (0 !== url.parse(req.url).pathname.indexOf(s.path)) return next();
      req.session = exports.readSession(s.session_key, s.secret, s.timeout, req);
      _writeHead = res.writeHead;
      res.writeHead = function(statusCode) {
        var args, cookiestr, headers, reasonPhrase, serializedData;
        reasonPhrase = null;
        headers = null;
        if ("string" === typeof arguments[1]) {
          reasonPhrase = arguments[1];
          headers = arguments[2] || {};
        } else {
          headers = arguments[1] || {};
        }
        cookiestr = null;
        if (!req.session) {
          if ("cookie" in req.headers) {
            cookiestr = escape(s.session_key) + '=';
            s.timeout = 0;
          }
        } else {
          serializedData = exports.serialize(s.secret, req.session);
          if (serializedData) {
            cookiestr = escape(s.session_key) + '=' + escape(serializedData);
          }
        }
        if (cookiestr) {
          if (s.useExpires) cookiestr += '; expires=' + exports.expires(s.timeout);
          if (s.useMaxAge) cookiestr += '; max-age=' + (s.timeout / 1000);
          if (s.path) cookiestr += '; path=' + s.path;
          if (s.domain) cookiestr += '; domain=' + s.domain;
          if (s.secure) cookiestr += '; secure';
          if (s.useHttpOnly) cookiestr += '; HttpOnly';
          if (Array.isArray(headers)) {
            headers.push(['Set-Cookie', cookiestr]);
          } else {
            if (headers['Set-Cookie']) {
              headers = exports.headersToArray(headers);
              headers.push(['Set-Cookie', cookiestr]);
            } else {
              headers['Set-Cookie'] = cookiestr;
            }
          }
        }
        args = [statusCode, reasonPhrase, headers];
        if (!args[1]) args.splice(1, 1);
        return _writeHead.apply(res, args);
      };
      return next();
    };
  };

  exports.readSession = function(session_key, secret, timeout, req) {
    var cookies;
    cookies = exports.readCookies(req);
    if (session_key in cookies && cookies[session_key]) {
      return exports.deserialize(secret, timeout, cookies[session_key]);
    } else {

    }
  };

  exports.readCookies = function(req) {
    var cookie, func, parts;
    if (req.cookies) {
      return req.cookies;
    } else {
      cookie = req.headers.cookie;
      if (!cookie) return {};
      parts = cookie.split(/\s*;\s*/g).map(function(x) {
        return x.split('=');
      });
      func = function(a, x) {
        a[unescape(x[0])] = unescape(x[1]);
        return a;
      };
      return parts.reduce(func, {});
    }
  };

  exports.headersToArray = function(headers) {
    var func;
    if (Array.isArray(headers)) return headers;
    func = function(arr, k) {
      arr.push([k, headers[k]]);
      return arr;
    };
    return Object.keys(headers).reduce(func, []);
  };

  exports.deserialize = function(secret, timeout, str) {
    var error;
    if (!exports.valid(secret, timeout, str)) {
      error = new Error('Invalid cookie');
      error.type = 'InvalidCookieError';
      return exports.Events.throwErr(error);
    }
    return JSON.parse(exports.decrypt(secret, exports.split(str).data_blob));
  };

  exports.serialize = function(secret, data) {
    var data_enc, data_str, hmac_sig, result, timestamp;
    data_str = JSON.stringify(data);
    data_enc = exports.encrypt(secret, data_str);
    timestamp = new Date().getTime();
    hmac_sig = exports.hmac_signature(secret, timestamp, data_enc);
    result = hmac_sig + timestamp + data_enc;
    if (!exports.checkLength(result)) {
      return exports.Events.throwErr('Data too long to store in a cookie');
    }
    return result;
  };

  exports.split = function(str) {
    return {
      hmac_signature: str.slice(0, 40),
      timestamp: parseInt(str.slice(40, 53), 10),
      data_blob: str.slice(53)
    };
  };

  exports.hmac_signature = function(secret, timestamp, data) {
    var hmac;
    hmac = crypto.createHmac('sha1', secret);
    hmac.update(timestamp + data);
    return hmac.digest('hex');
  };

  exports.valid = function(secret, timeout, str) {
    var hmac_sig, parts;
    parts = exports.split(str);
    hmac_sig = exports.hmac_signature(secret, parts.timestamp, parts.data_blob);
    return parts.hmac_signature === hmac_sig && new Date().getTime() < (parts.timestamp + timeout);
  };

  exports.decrypt = function(secret, str) {
    var decipher;
    decipher = crypto.createDecipher("aes192", secret);
    return decipher.update(str, 'hex', 'utf8') + decipher.final('utf8');
  };

  exports.encrypt = function(secret, str) {
    var cipher;
    cipher = crypto.createCipher("aes192", secret);
    return cipher.update(str, 'utf8', 'hex') + cipher.final('hex');
  };

  exports.checkLength = function(str) {
    return str.length <= MAX_LENGTH;
  };

  exports.expires = function(timeout) {
    return new Date(new Date().getTime() + timeout).toUTCString();
  };

  exports.Events = (function() {

    function Events() {}

    Events.onError = null;

    Events.throwErr = function(err) {
      if (typeof err !== "object") err = new Error(err);
      if (this.onError) {
        this.onError(err);
      } else {
        throw err;
      }
      return;
    };

    return Events;

  })();

}).call(this);
