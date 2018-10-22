# Cookie-Sessions

Secure cookie-based session middleware for Express.

Session data is stored on the request object in the 'session' property:
```js
  var app = require('express');
  var cookieSessions = require('cookie-sessions');

  app.use(
    cookieSessions({
      session_key: 'session_data',
      secret: process.env.SECRET
    })
  );
```

The session data can be any JSON object. It's timestamped, encrypted and
authenticated automatically. The authenticated encryption uses
`xsalsa20poly1305` offered by
[auth0-magic](https://github.com/auth0/magic) via
[magic.encrypt.sync](https://github.com/auth0/magic/#magicencryptsync--magicdecryptsync)
function. The httpOnly cookie flag is set by default.

The main function accepts a number of options:

  * secret -- The secret to encrypt the session data with. It has to be 32
    bytes long.
  * timeout -- The amount of time in miliseconds before the cookie expires
    (default: 24 hours)
  * sessionKey -- The cookie key name to store the session data in (default:
    \_node)
  * path -- The path to use for the cookie (default: '/')
  * domain -- (optional) Define a specific domain/subdomain scope for the
    cookie
  * secure -- (optional) Boolean, If true, the secure cookie flag will be set
  * sessionCookie -- (optional) Boolean, if true, it's considered a session
    cookie and no "expires" is set


## Why store session data in cookies?

* Its fast, you don't need to hit the filesystem or a database to look up
  session data
* It scales easily. You don't need to worry about sticky-sessions when
  load-balancing across multiple nodes.
* No server-side persistence requirements

## Caveats

* You can only store 4k of data in a cookie
* Higher-bandwidth requirements, since the cookie is sent to the server with
  every request.

__In summary:__ don't use cookie storage if you keep a lot of data in your
sessions!

## Migrating to version 1.0.0

* Any cookie created with 0.0.2 version will be invalidated.
* The secret used to encrypt the sessions data can no longer be of any length.
  It MUST be 32 bytes long and passed as either a Buffer object or a hex
  encoded string.
* The `options` object has two naming changes:
  * `sessionKey` instead of `session_key`
  * `sessionCookie` instead of `session_cookie`
* The following exported functions are now async and expect a callback:
  * readSession
  * serialize
  * deserialize
  * encrypt
  * decrypt
* The following exported functions have been removed:
  * readCookies
  * checkLength
  * headersToArray
  * hmac\_signature
