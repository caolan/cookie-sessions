crypto = require('crypto')
url = require('url')

# max allowable length of a cookie (4KB)
MAX_LENGTH = 4096


exports = module.exports = (settings) ->
    s =
        # key name
        session_key: '_node'
        # timeout/expiry (24 hours)
        timeout: 24 * 60 * 60 * 1000
        # path
        path: '/'
        # domain
        domain: null
        # https only?
        secure: false
        # use 'max-age' ?
        useMaxAge: true
        # use 'expires'?
        useExpires: true
        # use 'HttpOnly'?
        useHttpOnly: true
        # error handler
        onError: null

    # extend with passed-in settings
    for own k,v of settings
        s[k] = v

    # do we have an error handling callback?
    if "function" is typeof s.onError
        exports.Events.onError = s.onError

    # do some basic checks
    if not s.secret
        return exports.Events.throwErr 'No secret set in cookie-session settings'

    if "string" isnt typeof s.path or 0 isnt s.path.indexOf("/")
        return exports.Events.throwErr 'Invalid cookie path, must start with "/"'


    # Handle a request - the main method!
    return (req, res, next) ->
        # if the request is not under the specified path, do nothing.
        if 0 isnt url.parse(req.url).pathname.indexOf(s.path)
            return next()

        # Read session data from a request and store it in req.session
        req.session = exports.readSession(s.session_key, s.secret, s.timeout, req)

        # proxy writeHead to add cookie to response
        _writeHead = res.writeHead
        res.writeHead = (statusCode) =>

            reasonPhrase = null
            headers = null
            if "string" is typeof arguments[1]
                reasonPhrase = arguments[1]
                headers = arguments[2] or {}
            else
                headers = arguments[1] or {}


            # Add a Set-Cookie header to all responses with the session data
            # and the current timestamp. The cookie needs to be set on every
            # response so that the timestamp is up to date, and the session
            # does not expire unless the user is inactive.

            cookiestr = null
            # no session yet
            if not req.session
                if "cookie" of req.headers
                    cookiestr = escape(s.session_key) + '='
                    s.timeout = 0
            else
                serializedData = exports.serialize(s.secret, req.session)
                if serializedData
                    cookiestr = escape(s.session_key) + '=' + escape(serializedData)

            if cookiestr
                if s.useExpires  then cookiestr += '; expires=' + exports.expires(s.timeout)
                if s.useMaxAge   then cookiestr += '; max-age=' + (s.timeout / 1000) # In seconds
                if s.path        then cookiestr += '; path=' + s.path
                if s.domain      then cookiestr += '; domain=' + s.domain
                if s.secure      then cookiestr += '; secure'
                if s.useHttpOnly then cookiestr += '; HttpOnly'

                if Array.isArray(headers)
                    headers.push ['Set-Cookie', cookiestr]
                else
                    # if a Set-Cookie header already exists, convert headers to
                    # array so we can send multiple Set-Cookie headers.
                    if headers['Set-Cookie']
                        headers = exports.headersToArray(headers)
                        headers.push ['Set-Cookie', cookiestr]
                    else
                        # if no Set-Cookie header exists, leave the headers as an
                        # object, and add a Set-Cookie property
                        headers['Set-Cookie'] = cookiestr


            args = [statusCode, reasonPhrase, headers]
            # get rid of reasonPhrase if not defined
            if not args[1]
                args.splice(1, 1)

            # call the original writeHead on the request
            return _writeHead.apply res, args

        next()




# read session from given request cookie
# @return undefined if session data wasn't found or couldn't be read
exports.readSession = (session_key, secret, timeout, req) ->
    # Reads the session data stored in the cookie named 'key' if it validates,
    # otherwise returns an empty object.
    cookies = exports.readCookies(req)
    if session_key of cookies and cookies[session_key]
        return exports.deserialize(secret, timeout, cookies[session_key])
    else
        return undefined;


# read cookies from request object
exports.readCookies = (req) ->
    # if "cookieDecoder" is in use, then req.cookies
    # will already contain the parsed cookies
    if req.cookies
        return req.cookies
    else
        # Extracts the cookies from a request object.
        cookie = req.headers.cookie
        return {} if not cookie

        parts = cookie.split(/\s*;\s*/g).map (x) ->
            x.split('=')

        func = (a, x) ->
            a[unescape(x[0])] = unescape(x[1])
            a

        parts.reduce(func, {})



# convert key-value headers into arrays
exports.headersToArray = (headers) ->
    return headers if Array.isArray(headers)
    func = (arr, k) ->
        arr.push [k, headers[k]]
        arr
    Object.keys(headers).reduce(func, [])


# parse cookie data
# @return undefined if data couldn't be parsed
exports.deserialize = (secret, timeout, str) ->
    # Parses a secure cookie string, returning the object stored within it.
    # Returns undefined (and sends out an error) if the secure cookie string does not validate.
    if not exports.valid(secret, timeout, str)
        error = new Error('Invalid cookie')
        error.type = 'InvalidCookieError'
        return exports.Events.throwErr(error)
    JSON.parse(exports.decrypt(secret, exports.split(str).data_blob))


# construct cookie data
# @return undefined if data couldn't be constructed
exports.serialize = (secret, data) ->
    # Turns a JSON-compatibile object literal into a secure cookie string
    data_str = JSON.stringify(data)
    data_enc = exports.encrypt(secret, data_str)
    timestamp = new Date().getTime()
    hmac_sig = exports.hmac_signature(secret, timestamp, data_enc)
    result = hmac_sig + timestamp + data_enc
    if not exports.checkLength(result)
        return exports.Events.throwErr 'Data too long to store in a cookie'
    result


exports.split = (str) ->
    # Splits a cookie string into hmac signature, timestamp and data blob.
    return {
        hmac_signature: str.slice(0,40)
        timestamp: parseInt(str.slice(40, 53), 10)
        data_blob: str.slice(53)
    }


# calculate hmac signature
exports.hmac_signature = (secret, timestamp, data) ->
    # Generates a HMAC for the timestamped data, returning the
    # hex digest for the signature.
    hmac = crypto.createHmac('sha1', secret)
    hmac.update(timestamp + data);
    hmac.digest('hex')


exports.valid = (secret, timeout, str) ->
    # Tests the validity of a cookie string. Returns true if the HMAC
    # signature of the secret, timestamp and data blob matches the HMAC in the
    # cookie string, and the cookie's age is less than the timeout value.
    parts = exports.split(str)
    hmac_sig = exports.hmac_signature secret, parts.timestamp, parts.data_blob
    return parts.hmac_signature is hmac_sig and
        new Date().getTime() < (parts.timestamp + timeout)


exports.decrypt = (secret, str) ->
    # Decrypt the aes192 encoded str
    decipher = crypto.createDecipher("aes192", secret)
    decipher.update(str, 'hex', 'utf8') + decipher.final('utf8')


exports.encrypt = (secret, str) ->
    # Encrypt the str with aes192 using secret.
    cipher = crypto.createCipher("aes192", secret)
    cipher.update(str, 'utf8', 'hex') + cipher.final('hex')


exports.checkLength = (str) ->
    # Test if a string is within the maximum length allowed for a cookie (4KB.
    return str.length <= MAX_LENGTH


# Generates an expires date
# exports.params timeout the time in milliseconds before the cookie expires
exports.expires = (timeout) ->
    new Date(new Date().getTime() + timeout).toUTCString();


# events delegate
class exports.Events
    # The error-handling callback
    @onError: null

    # Throw an error
    # @param errObj an Error object or error message
    # @return undefined
    @throwErr: (err) ->
        if typeof err isnt "object"
            err = new Error(err)
        if @onError then @onError(err) else throw err
        undefined



