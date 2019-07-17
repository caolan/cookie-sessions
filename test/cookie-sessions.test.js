var sessions = require('../lib/cookie-sessions');
var assert  = require('assert')
var sinon = require('sinon')
var crypto = require('crypto')
var request = require('supertest');
var express = require('express');
var cookieParser = require('cookie-parser')

describe('cookie sessions tests', function() {
  var secret = '8c06bdc84bf095d76b18c1e3a485dfe6'
  var message = 'the answer to the ultimate question of life, the universe, and everything'
  var encr = '017cb25516cf63f676e680abf99e2797da7f0765b3f19e53adbdadfaf2cd8f9a9378a35b1e52fb00e2a5aa577eb277d98096dbb75afd9dd57b0498e54ead8fc66ed980bf1e60a1b2b8'
  var iv = '55df03d8dd90145b7f23211613d46b2d'
  var authTag = 'c9e0fe9af2412ce941d18e7eae667402'
  var user_data = {
    id: 123,
    username: 'foobar',
    email: 'foobar@gmail.com',
    role: 'user'
  }

  beforeEach(function () {
    this.sandbox = sinon.createSandbox();
  });

  afterEach(function () {
    this.sandbox.restore();
  });

  describe('encrypt', function() {
    it('should sucessfully return encrypted data', function() {
      enc = sessions.encrypt(secret, message)
      assert.ok(enc.ciphertext)
      assert.ok(enc.iv)
      assert.ok(enc.authTag)
    })
  })

  describe('decrypt', function() {
    it('should sucessfully return decrypted data', function() {
      plaintext = sessions.decrypt(secret, encr, iv, authTag)
      assert.equal(message, plaintext)
    })
  })

  describe('serialize', function() {
    it('should return a string', function() {
      var result = sessions.serialize(secret, user_data, 1540678757323,  false)
      var arr = result.split('$')
      var cipher = arr[0]
      var iv = arr[1]
      var authTag = arr[2]
      assert.ok(cipher)
      assert.ok(iv)
      assert.ok(authTag)
    })

    it('should return error on long data', function() {
      var  long = '';
      for(var i = 0; i < 1500; i++){
          long += 'a';
      };
      this.sandbox.stub(sessions, 'encrypt').returns({ciphertext: long, iv: long, authTag: long});
      try {
        var cookiestr = sessions.serialize(secret, user_data)
      }
      catch(err) {
        assert.equal(err.message, 'Data too long to store in a cookie')
      };
    })
  })

  describe('deserialize', function() {
    it('should return user data in JSON if cookie has not expired', function() {
      var cookiestr = sessions.serialize(secret, user_data, Date.now(), false)
      var jsonData = sessions.deserialize(secret, cookiestr, 1000 * 60 * 60 * 12)
      assert.deepEqual(jsonData.data, user_data)
    })

    it('should return validation error if cookie has expired', function() {
      var str = '3d11d4581d2359247a4183fc3c84aceaa5835d38075117b10c1f8bcff4a63f0d3740f6ff30f60942b9851af38fd8f1d5bcf6b2376c6803f001a844dc71b5d50276cbb735f501c47d320ef6c6d07cd2047b7a6b26521c23687718ebf248bd9b$69d2b05d79b47c3e5a94b0f32f2fbe3b$ed4c06a57df5a2b646f7e5f82bffb17f'
      try {
        var jsonData = sessions.deserialize(secret, str, 1000 * 60 * 60 * 10)
      }
      catch(err) {
        assert.ok(err)
        assert.equal(err.message, 'Cookie expired')
      }
    })
  })

  describe('onInit', function() {
    it('throw error if no secret set in server settings', function() {
      try {
        sessions({})
      } catch(err) {
        assert.ok(err)
        assert.equal(err.message, 'No secret set in cookie-session settings')
      }
    });
    it('throw error for invalid path', function() {
      try {
        sessions({secret: secret, path: 'foo/bar'})
      } catch(err) {
        assert.ok(err)
        assert.equal(err.message, 'Invalid cookie path, must start with "/"')
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
    it('throw error for invalid value in sameSite option', function() {
      try {
        sessions({secret: secret, sameSite: true})
      } catch(err) {
        assert.ok(err)
        assert.equal(err.message, 'Possible values for sameSite option: "lax" or "strict"')
      }
    });
  })

  describe('the middleware', function() {
    beforeEach(function () {
      this.app = express();
    });

    describe('when session has already data', function() {
      beforeEach(function() {
        this.cookieTime = Date.now()
        this.sandbox.stub(sessions, 'deserialize').returns({data: {username: 'foobar'}, time: this.cookieTime});
      });

      describe('and new data are added to req.session', function() {
        describe('and autoRenew is set to true', function() {
          it('should set a new cookie with the combined data and with new timestamp', function () {
            this.app.use(cookieParser())
            this.app.use(sessions({secret: secret, autoRenew: true}))
            this.app.get('/', (req, res) => {
              req.session.koko = 'bar'
              res.send('Hello World!')
            })
            return request(this.app)
            .get('/')
            .then(res => {
              this.sandbox.restore();
              assert(res.headers['set-cookie'])
              _node = res.headers['set-cookie'][0].split(';')[0].split('=')[1]
              var jsonData = sessions.deserialize(secret, decodeURIComponent(_node), 1000 * 60 * 60 * 24)
              assert.notEqual(jsonData.time, this.cookieTime)
              assert.deepEqual(jsonData.data, { username: 'foobar', koko: 'bar' })
            })
          });
        });
        describe('and autoRenew is set to false', function() {
          it('should set a new cookie with the combined data and the initial timestamp', function () {
            this.app.use(cookieParser())
            this.app.use(sessions({secret: secret, autoRenew: false}))
            this.app.get('/', (req, res) => {
              req.session.koko = 'bar'
              res.send('Hello World!')
            })
            return request(this.app)
            .get('/')
            .then(res => {
              this.sandbox.restore();
              assert(res.headers['set-cookie'])
              var _node = res.headers['set-cookie'][0].split(';')[0].split('=')[1]
              var jsonData = sessions.deserialize(secret, decodeURIComponent(_node), 1000 * 60 * 60 * 24)
              assert.equal(jsonData.time, this.cookieTime)
              assert.deepEqual(jsonData.data, { username: 'foobar', koko: 'bar' })
            })
          });
        });
      });
      describe('and no data are added to req.session', function() {
        describe('and autoRenew is set to true', function() {
          it('should set a new cookie with new timestamp', function () {
            this.app.use(cookieParser())
            this.app.use(sessions({secret: secret, autoRenew: true}))
            this.app.get('/', (req, res) => {
              res.send('Hello World!')
            })
            return request(this.app)
            .get('/')
            .then(res => {
              this.sandbox.restore();
              assert(res.headers['set-cookie'])
              var _node = res.headers['set-cookie'][0].split(';')[0].split('=')[1]
              var jsonData = sessions.deserialize(secret, decodeURIComponent(_node), 1000 * 60 * 60 * 24)
              assert.notEqual(jsonData.time, this.cookieTime)
              assert.deepEqual(jsonData.data, { username: 'foobar'})
            })
          });
        });
        describe('and autoRenew is set to false', function() {
          it('should not set a new cookie', function () {
            this.app.use(cookieParser())
            this.app.use(sessions({secret: secret, autoRenew: false}))
            this.app.get('/', (req, res) => {
              res.send('Hello World!')
            })
            return request(this.app)
            .get('/')
            .then(res => {
              this.sandbox.restore();
              assert(!res.headers['set-cookie'])
            })
          });
        });
      });
      describe('data get deleted from req.session', function() {
        it('should set a new cookie with empty data', function () {
          this.app.use(cookieParser())
          this.app.use(sessions({secret: secret}))
          this.app.get('/', (req, res) => {
            req.session = {}
            res.send('Hello World!')
          })
          this.sandbox.restore();
          var cookiestr = sessions.serialize(secret, user_data, Date.now(),  false)
          return request(this.app)
          .get('/')
          .set('Cookie', '_node=' + encodeURIComponent(cookiestr))
          .then(res => {
            assert(res.headers['set-cookie'])
            var _node = res.headers['set-cookie'][0].split(';')[0].split('=')[1]
            var jsonData = sessions.deserialize(secret, decodeURIComponent(_node), 1000 * 60 * 60 * 24)
            assert.deepEqual(jsonData.data, {})
          })
        });
      });
    });
    describe('when session is empty', function() {
      describe('and new data are added to req.session', function() {
        it('should set a new cookie with the new data and with a timestamp', function () {
          this.sandbox.stub(sessions, 'deserialize').returns({data: {}});
          this.app.use(cookieParser())
          this.app.use(sessions({secret: secret}))
          this.app.get('/', (req, res) => {
            req.session.koko = 'bar'
            res.send('Hello World!')
          })
          return request(this.app)
          .get('/')
          .then(res => {
            this.sandbox.restore()
            assert(res.headers['set-cookie'])
            var _node = res.headers['set-cookie'][0].split(';')[0].split('=')[1]
            var jsonData = sessions.deserialize(secret, decodeURIComponent(_node), 1000 * 60 * 60 * 24)
            assert(jsonData.time)
            assert.deepEqual(jsonData.data, { koko: 'bar' })
          })
        });
      });
    });
  })
})
