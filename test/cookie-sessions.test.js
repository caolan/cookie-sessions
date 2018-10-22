var sessions = require('../lib/cookie-sessions');
var assert  = require('assert')
var sinon = require('sinon')
var crypto = require('crypto')
var sandbox;

describe('cookie sessions tests', () => {
  var secret = '63e973cd82855e4f5669af6d7fa0ec4be02474871c155ead81a669474adc5e61'
  var message = 'the answer to the ultimate question of life, the universe, and everything'
  var encr = '8c17200a08910652154d41b561242f4ff4672e4caf2ac71fc29b40cbe8f1451519e333f26f6b87fbda5e29220171dc350d67b537ee7ac02d2e6dd4f25597de27727a70c2e196242026a15daffaaf6bc9230b03b5786879e9bd'
  var nonce = '074800982ca4f120b37acaf86c4997769100843d466e5595'
  var user_data = {
    id: 123,
    username: 'foobar',
    email: 'foobar@gmail.com',
    role: 'user'
  }

  beforeEach(function () {
    sandbox = sinon.createSandbox();
  });

  afterEach(function () {
    sandbox.restore();
  });

  describe('encrypt', () => {
    it('should sucessfully return encrypted data', (done) => {
      sessions.encrypt(secret, message, (err, result) => {
        assert.ok(!err)
        done();
      });
    })
  })

  describe('decrypt', () => {
    it('should sucessfully return decrypted data', (done) => {
      sessions.decrypt(secret, encr, nonce, (err, plaintext) => {
        assert.equal(message, plaintext)
        done();
      });
    })
  })

  describe('serialize', () => {
    it('should return a string', (done) => {
      sessions.serialize(secret, user_data, (err, result) => {
        assert.ok(!err)
        var arr = result.split('$')
        var nonce = arr[0]
        var cipher = arr[1]
        assert.ok(nonce)
        assert.ok(cipher)
        done();
      });
    })

    it('should return error on long data', (done) => {
      var  long = '';
      for(var i=0; i<2050; i++){
          long += 'a';
      };
      sandbox.stub(sessions, 'encrypt').yields(null, {ciphertext: long, nonce: long});
      sessions.serialize(secret, user_data, (err, result) => {
        assert.ok(err)
        assert.equal(err.message, 'Data too long to store in a cookie')
        done();
      });
    })
  })

  describe('deserialize', () => {
    it('should return user data in JSON if cookie has not expired', (done) => {
      sessions.serialize(secret, user_data, (err, result) => {
        sessions.deserialize(secret, result, 1000 * 60 * 60 * 24, (err, data) => {
          assert.ok(!err)
          assert.deepEqual(data, user_data)
          done();
        });
      });
    })

    it('should return validation error if cookie has expired', (done) => {
      var str = 'b5a8af11ce10cd632796df523c9142595b472b686738f6a6$29d28d5d9c63b3daf6d628626b5ce3d045dc506321579af014b7eda3665e84342f65c97f79df314b7991255a41585e325e7a6e7e0218485c27af644cc1517e81801dae85716deeea32fbdccebda1ed59a3b3a1ec689447d5a39d6a37c4541623ef93ffc0ca2fb17cd20e4708a7fab59e3f87c5c5afa277b66bd3'
      sessions.deserialize(secret, str, 1000 * 60 * 60 * 24, (err, data) => {
        assert.ok(err)
        assert.equal(err.message, 'Cookie expired')
        done();
      });
    })
  })

  describe('readSession', () => {
    it('session with key node_session read ok', () => {
      sandbox.stub(sessions, 'deserialize').yields(null, {username: 'foobar'});
      sessions.readSession('node_session', secret, 12, {cookies: {node_session: 'lala'}} , (err, data) => {
        assert.ok(!err)
        assert.deepEqual({username: 'foobar'}, data)
      })
    });
  })

  describe('onInit', () => {
    it('throw exception if no secret set in server settings', () => {
      try {
        sessions({})
      } catch(err) {
        assert.ok(err)
        assert.equal(err.message, 'No secret set in cookie-session settings')
      }
    });
    it('throw exception for invalid path', () => {
      try {
        sessions({path: 'foo/bar'})
      } catch(err) {
        assert.ok(err)
        assert.equal(err.message, 'No secret set in cookie-session settings')
      }
    });
    it('should do nothing for a request not under the specified path', (done) => {
      const session = sessions({path: '/foo/bar', secret: secret })
      req = { path: '/foo/baz' }
      res = {}
      next = function() {
        assert.ok(!req.session)
        done()
      }
      session(req, res, next)
    });
  })
})
