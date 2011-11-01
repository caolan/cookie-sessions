var crypto = require('crypto');
var url = require('url');

var exports = module.exports = function(settings){

    var default_settings = {
        // don't set a default cookie secret, must be explicitly defined
        session_key: '_node',
        timeout: 1000 * 60 * 60 * 24, // 24 hours
        path: '/'
    };
    var s = extend(default_settings, settings);
    if(!s.secret) throw new Error('No secret set in cookie-session settings');

    if(typeof s.path !== 'string' || s.path.indexOf('/') != 0)
        throw new Error('invalid cookie path, must start with "/"');

    return function(req, res, next){
        // if the request is not under the specified path, do nothing.
        if (url.parse(req.url).pathname.indexOf(s.path) != 0) {
            next();
            return;
        }

        // Read session data from a request and store it in req.session
        req.session = exports.readSession(
            s.session_key, s.secret, s.timeout, req);

        var writeHead = res.writeHead;
        res.writeHead = function(status, headers){
          // TODO: In the old version a session-cookie will be set on every request.
          //       It has to be checked whether this is useful or not.
          if (req.session) {
            res.setHeader('Set-Cookie', buildCookieStr(s, req.session));
          }

          res.writeHead = writeHead;
          return res.writeHead(status, headers);
        };

        // TODO: This is from connect/session, which works fine with other SessionStores.
        //       It has to be checked whether this us useful in out circumstance.
        var end = res.end;
        res.end = function(data, encoding) {
          res.end = end;
          // HACK: ensure Set-Cookie for implicit writeHead()
          if (req.session && !res._header) {
            res._implicitHeader();
          }
          res.end(data, encoding);
        };

        next();

    };
};

// Extend a given object with all the properties in passed-in object(s).
// From underscore.js (http://documentcloud.github.com/underscore/)
function extend(obj) {
    Array.prototype.slice.call(arguments).forEach(function(source) {
      for (var prop in source) obj[prop] = source[prop];
    });
    return obj;
};

function buildCookieStr(settings, session) {
  return escape(settings.session_key) + '='
      + escape(exports.serialize(settings.secret, session))
      + '; expires=' + exports.expires(settings.timeout)
      + '; path=' + settings.path + '; HttpOnly';
};

exports.deserialize = function(secret, timeout, str){
    // Parses a secure cookie string, returning the object stored within it.
    // Throws an exception if the secure cookie string does not validate.

    if(!exports.valid(secret, timeout, str)){
        throw new Error('invalid cookie');
    }
    var data = exports.decrypt(secret, exports.split(str).data_blob);
    var timestamp = exports.split(str).timestamp;
    var json = JSON.parse(data);
    json.timestamp = timestamp;
    return json;
};

exports.serialize = function(secret, data){
    // Turns a JSON-compatibile object literal into a secure cookie string

    var data_str = JSON.stringify(data);
    var data_enc = exports.encrypt(secret, data_str);
    var timestamp = (new Date()).getTime();
    var hmac_sig = exports.hmac_signature(secret, timestamp, data_enc);
    var result = hmac_sig + timestamp + data_enc;
    if(!exports.checkLength(result)){
        throw new Error('data too long to store in a cookie');
    }
    return result;
};

exports.split = function(str){
    // Splits a cookie string into hmac signature, timestamp and data blob.
    return {
        hmac_signature: str.slice(0,40),
        timestamp: parseInt(str.slice(40, 53), 10),
        data_blob: str.slice(53)
    };
};

exports.hmac_signature = function(secret, timestamp, data){
    // Generates a HMAC for the timestamped data, returning the
    // hex digest for the signature.
    var hmac = crypto.createHmac('sha1', secret);
    hmac.update(timestamp + data);
    return hmac.digest('hex');
};

exports.valid = function(secret, timeout, str){
    // Tests the validity of a cookie string. Returns true if the HMAC
    // signature of the secret, timestamp and data blob matches the HMAC in the
    // cookie string, and the cookie's age is less than the timeout value.

    var parts = exports.split(str);
    var hmac_sig = exports.hmac_signature(
        secret, parts.timestamp, parts.data_blob
    );
    return (
        parts.hmac_signature === hmac_sig &&
        parts.timestamp + timeout > new Date().getTime()
    );
};

exports.decrypt = function(secret, str){
    // Decrypt the aes192 encoded str using secret.
    var decipher = crypto.createDecipher("aes192", secret);
    return decipher.update(str, 'hex', 'utf8') + decipher.final('utf8');
};

exports.encrypt = function(secret, str){
    // Encrypt the str with aes192 using secret.
    var cipher = crypto.createCipher("aes192", secret);
    return cipher.update(str, 'utf8', 'hex') + cipher.final('hex');
};

exports.checkLength = function(str){
    // Test if a string is within the maximum length allowed for a cookie.
    return str.length <= 4096;
};

exports.readCookies = function(req){
    // if "cookieDecoder" is in use, then req.cookies
    // will already contain the parsed cookies
    if (req.cookies) {
        return req.cookies;
    }
    else {
        // Extracts the cookies from a request object.
        var cookie = req.headers.cookie;
        if(!cookie){
            return {};
        }
        var parts = cookie.split(/\s*;\s*/g).map(function(x){
            return x.split('=');
        });
        return parts.reduce(function(a, x){
            a[unescape(x[0])] = unescape(x[1]);
            return a;
        }, {});
    }
};

exports.readSession = function(key, secret, timeout, req){
    // Reads the session data stored in the cookie named 'key' if it validates,
    // otherwise returns an empty object.

    var cookies = exports.readCookies(req);
    if(cookies[key]){
        return exports.deserialize(secret, timeout, cookies[key]);
    }
    return undefined;
};


exports.expires = function(timeout){
    return (new Date(new Date().getTime() + (timeout))).toUTCString();
};
