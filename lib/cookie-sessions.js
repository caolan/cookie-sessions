var magic = require('auth0-magic')
var url = require('url');

var MAX_LENGTH = 4096;

var exports = module.exports = function(settings) {
  // don't set a default cookie secret, must be explicitly defined
  var defaultSettings = {
    sessionKey: '_node',
    timeout: 1000 * 60 * 60 * 24, // 24 hours
    path: '/',
    httpOnly: true,
    secure: true
  };

  var opts = Object.assign({}, defaultSettings, settings)

  if (!opts.secret) {
    throw new Error('No secret set in cookie-session settings');
  }
  if ((typeof opts.secret === 'string' && opts.secret.length !== 64) ||
      (Buffer.isBuffer(opts.secret) && opts.secret.length !== 32)) {
    throw new Error('Invalid secret length');
  }

  if (typeof opts.path !== 'string' || opts.path.indexOf('/') !== 0) {
    throw new Error('Invalid cookie path, must start with "/"');
  }

  return function(req, res, next) {
    // if the request is not under the specified path, do nothing.
    if (req.path.indexOf(opts.path) !== 0) {
      next();
      return;
    }

    // Read session data from a request and store it in req.session
    exports.readSession(opts.session_key, opts.secret, opts.timeout, req, (err, session) => {
      if (err) {
        session = null
      }
      req.session = session;

      var options = {
        path: opts.path,
        httpOnly: true,
        domain: opts.domain,
        httpOnly: opts.httpOnly,
        secure: opts.secure
      };

      // If the session is undefined, no cookie is sent (and the cookie is
      // cleared if it is already set). If a session exists, we add a
      // Set-Cookie header to all responses with the session data and the
      // current timestamp. The cookie needs to be set on every response so
      // that the timestamp is up to date, and the session does not expire
      // unless the user is inactive.
      if (req.session === null) {
        if (req.cookies[opts.session_key]) {
          if (!opts.sessionCookie) {
            options.expires = exports.expires(0);
          };

          res.cookie(opts.session_key, '', options)
        }
        next();
        return;
      } else {
        if (!opts.sessionCookie) {
          options.expires = exports.expires(opts.timeout);
        }
        exports.serialize(opts.secret, req.session, (err, cookieData) => {
          if (err) {
            next(err)
            return;
          }
          res.cookie(opts.session_key, cookieData, options)
          next();
          return;
        })
      }
    })
  };
};

exports.split = function(str){
  var arr = str.split('$')
  return {
    nonce: arr[0],
    ciphertext: arr[1]
  };
};


exports.valid = function(timestamp, timeout) {
  return timestamp + timeout > Date.now();
}

exports.expires = function(timeout) {
  if (timeout) {
    return new Date(Date.now() + timeout);
  }
  return null;
};

exports.encrypt = function(secret, message, cb) {
  magic.encrypt.sync(message, secret, (err, output) => {
    if (err) {
      return cb(err)
    }
    cb(
      null,
      { ciphertext: output.ciphertext.toString('hex'),
        nonce: output.nonce.toString('hex')
      }
    )
  })
};

exports.decrypt = function(secret, ciphertext, nonce, cb) {
  magic.decrypt.sync(secret, ciphertext, nonce, (err, plaintext) => {
    if (err) {
      return cb(err)
    }
    cb(null, plaintext.toString('utf-8'))
  });
};

// Turns a JSON-compatibile object literal into a secure cookie string
exports.serialize = function(secret, data, cb) {
  var cookieData = {
    d: data,
    t: Date.now()
  }
  var data_str = JSON.stringify(cookieData);
  exports.encrypt(secret, data_str, (err, result) => {
    if (err) {
      return cb(new Error('Failed to encrypt cookie'))
    }
    var result = result.nonce + '$' + result.ciphertext;
    if (result.length > MAX_LENGTH) {
      return cb(new Error('Data too long to store in a cookie')) ;
    }
    cb(null, result);
  })
}

// Parses a secure cookie string, returning the object stored within it.
exports.deserialize = function(secret, str, timeout, cb) {
  var splited = exports.split(str)
  exports.decrypt(secret, splited.ciphertext, splited.nonce, (err, cookieData) => {
    if (err) {
      cb(new Error('Failed to decrypt cookie'))
      return;
    }
    var jsonData = JSON.parse(cookieData)

    if (!exports.valid(jsonData.t, timeout)) {
      return cb(new Error('Cookie expired'))
    }
    cb(null, jsonData.d);
  });
};

 // Reads the session data stored in the cookie named 'key' if it validates,
 // otherwise returns null.
exports.readSession = function(key, secret, timeout, req, cb) {
  if (req.cookies && req.cookies[key]) {
    exports.deserialize(secret, req.cookies[key], timeout, cb);
  } else {
    cb(null, null);
  }
};
