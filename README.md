# Cookie-Sessions

Secure cookie-based session middleware for Express.

Session data is stored on the request object in the 'session' property:
```js
  var app = require('express');
  var cookieParser = require('cookie-parser');
  var cookieSessions = require('cookie-sessions');

  app.use(
    cookieSessions({
      name: 'session_data',
      secret: process.env.SECRET
    })
  );
```

The [cookie-parser](https://www.npmjs.com/package/cookie-parser) middleware
MUST also used.

The session data can be any JSON object. It's timestamped, encrypted and
authenticated automatically. The authenticated encryption uses `aes-256-gcm`
offered by the node `crypto` library. The httpOnly and secure cookie flags are
set by default.

The main function accepts a number of options:

| Option        | Required | Description                                                                                                             | Default  |
|---------------|----------|-------------------------------------------------------------------------------------------------------------------------|----------|
| secret        | Yes      | The secret to encrypt the session data.                                                                                 |          |
| timeout       | Yes      | The amount of time in milliseconds before the cookie expires.                                                           | 24 hours |
| name          | Yes      | The cookie name in which to store the session data.                                                                     | `\_node` |
| path          | Yes      | The path to use for the cookie.                                                                                         | `/`      |
| domain        | No       | Define a specific domain/subdomain scope for the cookie.                                                                |          |
| autoRenew     | No       | Boolean: if true, a new cookie will be set in each response with an updated expiration Date.now() + timeout             |   true   |
| httpOnly      | No       | Boolean: if true, the httpOnly cookie flag will be set.                                                                 |   true   |
| secure        | No       | Boolean: if true, the secure cookie flag will be set.                                                                   |   true   |
| sameSite      | No       | If set to "lax" or "strict", the sameSite cookie flag with the corresponding mode will be set.                          |          |
| sessionCookie | No       | Boolean: if true, it's considered a session cookie and no "expires" is set.                                             |          |


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
* The `options` object has two naming changes:
  * `name` instead of `session_key`
  * `sessionCookie` instead of `session_cookie`
* The following exported functions have been removed:
  * readSession
  * readCookies
  * checkLength
  * headersToArray
  * hmac\_signature
