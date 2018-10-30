var _ = require('lodash')
var crypto = require('crypto')

const MAX_LENGTH = 4096;

// don't set a default cookie secret, must be explicitly defined
const DEFAULT_SETTINGS = {
  name: '_node',
  timeout: 1000 * 60 * 60 * 24, // 24 hours
  path: '/',
  autoRenew: true,
  httpOnly: true,
  secure: true
};

var exports = module.exports = function(settings) {
  var opts = Object.assign({}, DEFAULT_SETTINGS, settings)

  if (!opts.secret) {
    throw new Error('No secret set in cookie-session settings');
  }

  if (typeof opts.path !== 'string' || opts.path.indexOf('/') !== 0) {
    throw new Error('Invalid cookie path, must start with "/"');
  }

  if (opts.sameSite && (opts.sameSite !== 'lax' || opts.sameSite !== 'strict')) {
    throw new Error('Possible values for sameSite option: "lax" or "strict"');
  }

  return function(req, res, next) {

    // if the request is not under the specified path, do nothing.
    if (req.path.indexOf(opts.path) !== 0) {
      next();
      return;
    }
    req.session = {}

    // Read session data from a request and store it in req.session
    var session = {
      data: {}
    }
    try {
      session = exports.deserialize(opts.secret, req.cookies[opts.name], opts.timeout);
      req.session = session.data
    } catch (err) {
    }
    var oldSession = _.cloneDeep(req.session)

    var options = _.pick(opts, [ 'path', 'domain', 'httpOnly', 'secure', 'sameSite' ])

    var _writeHead = res.writeHead;
    res.writeHead = function() {
      // only set cookie if autoRenew is on or session data changed
      if (opts.autoRenew || !_.isEqual(oldSession, req.session)) {
        /*
         * If the session is empty, no cookie is sent (and the cookie is
         * cleared if it is already set). If a session exists, we add a
         * Set-Cookie header to all responses with the session data and the
         * current timestamp. The cookie needs to be set on every response so
         * that the timestamp is up to date, and the session does not expire
         * unless the user is inactive.
         */
        if (_.isEqual(req.session, {})) {
          if (req.cookies[opts.name]) {
            res.clearCookie(opts.name, options)
          }
        } else {
          if ((!opts.sessionCookie || !opts.autoRenew) && opts.timeout) {
            options.expires = new Date(Date.now() + opts.timeout);
          }
          try {
            cookiestr = exports.serialize(opts.secret, req.session, session.time, opts.autoRenew)
          } catch(err) {
            cookiestr = ''
          }
          res.cookie(opts.name, cookiestr, options)
        }
      }

      return _writeHead.apply(res, arguments);
    }
    next()
  };
};

exports.split = function(str){
  var arr = str.split('$')
  return {
    ciphertext: arr[0],
    iv: arr[1],
    authTag: arr[2]
  };
};

exports.merge = function(obj) {
  return [ obj.ciphertext, obj.iv, obj.authTag ].join('$')
};

exports.valid = function(timestamp, timeout) {
  return timestamp + timeout > Date.now();
}

exports.encrypt = function(secret, message) {
  try {
    var iv = crypto.randomBytes(16);
    var cipher = crypto.createCipheriv('aes-256-gcm', secret, iv);
    var ciphertext = cipher.update(message, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    return {
      ciphertext: ciphertext,
      iv: iv.toString('hex'),
      authTag: cipher.getAuthTag().toString('hex')
    };
  } catch(err) {
    throw new Error('Failed to encrypt cookie')
  }
};

exports.decrypt = function(secret, ciphertext, iv, authTag) {
  try {
    var decipher = crypto.createDecipheriv('aes-256-gcm', secret, Buffer.from(iv, 'hex'));
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    var plaintext = decipher.update(ciphertext, 'hex', 'utf8');
    plaintext += decipher.final('utf8');
    return plaintext;
  } catch(err) {
    throw new Error('Failed to decrypt and authenticate cookie')
  }
};

// Turns a JSON-compatibile object literal into a secure cookie string
exports.serialize = function(secret, data, sessionTime, autoRenew) {
  if (autoRenew || typeof sessionTime === 'undefined') {
    sessionTime = Date.now()
  }
  var cookieData = {
    d: data,
    t: sessionTime
  }
  var dataStr = JSON.stringify(cookieData);
  var enc = exports.encrypt(secret, dataStr)
  var result = exports.merge(enc)
  if (result.length > MAX_LENGTH) {
    throw Error('Data too long to store in a cookie') ;
  }
  return result
}

// Parses a secure cookie string, returning the object stored within it.
exports.deserialize = function(secret, str, timeout) {
  if (!str) {
    return {
      data: {}
    }
  }
  var splitted = exports.split(str)
  cookieData = exports.decrypt(secret, splitted.ciphertext, splitted.iv, splitted.authTag)
  var jsonData = JSON.parse(cookieData)

  if (!exports.valid(jsonData.t, timeout)) {
    throw new Error('Cookie expired')
  }
  return {
    data: jsonData.d,
    time: jsonData.t
  }
};
