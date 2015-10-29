expect = require("chai").expect
JWKS = require "../lib"
Promise = require "bluebird"

sampleKey1 =
    kty: "EC"
    kid: "testKey1"
    crv: "P-256"
    x: "uiOfViX69jYwnygrkPkuM0XqUlvW65WEs_7rgT3eaak"
    y: "v8S-ifVFkNLoe1TSUrNFQVj6jRbK1L8V-eZa-ngsZLM"
    d: "dI5TRpZrVLpTr_xxYK-n8FgTBpe5Uer-8QgHu5gx9Ds"
sampleKeySet = keys: [ sampleKey1 ]
emptyKeySet = keys: [ ]

testLoaderKeySet = null
testLoader =
    loadAsync: (check) -> return Promise.resolve value: testLoaderKeySet, loaded: check
    reset: () ->

describe "JWKS Crypto Helpers", () ->
    describe "Signature", () ->
        it "Should round-trip", (done) ->
            payload = test: "XYZZY"

            t = new JWKS jwks: sampleKeySet
            t.getKeyAsync kid: "testKey1"
            .then (key) -> t.signAsync key, JSON.stringify payload
            .then (rv) ->
                expect(rv).to.be.ok
                t.verifySignatureAsync rv
            .then (rv) ->
                expect(rv).to.be.ok
                expect(rv.header).to.deep.equal(alg: "ES256", kid: "testKey1")
                t2 = JSON.parse rv.payload.toString "utf8"
                expect(t2).to.deep.equal(payload)

            .then () -> done()
            .catch done

        it "Should round-trip (with key search)", (done) ->
            payload = test: "XYZZY"

            t = new JWKS jwks: sampleKeySet
            t.signAsync { kid: "testKey1" }, JSON.stringify payload
            .then (rv) ->
                expect(rv).to.be.ok
                t.verifySignatureAsync rv
            .then (rv) ->
                expect(rv).to.be.ok
                expect(rv.header).to.deep.equal(alg: "ES256", kid: "testKey1")
                t2 = JSON.parse rv.payload.toString "utf8"
                expect(t2).to.deep.equal(payload)

            .then () -> done()
            .catch done

        it "Should fail if no key is found", (done) ->
            payload = test: "XYZZY"

            t = new JWKS jwks: sampleKeySet
            t.signAsync { kid: "testKey99999" }, JSON.stringify payload
            .then () -> done new Error "Unexpected signing success in failure unit test"
            .catch (err) ->
                if err.message == "No signing key found" then done()
                else done err

        it "Should throw error if key is not found", (done) ->
            payload = test: "XYZZY"

            k1 = null
            t = new JWKS jwks: sampleKeySet
            t.getKeyAsync kid: "testKey1"
            .then (key) ->
                k1 = key
                t.signAsync key, JSON.stringify payload
            .then (rv) ->
                t.removeKeyAsync k1
                .then () -> t.verifySignatureAsync rv
            .then (rv) -> throw new Error "Unexpected signature validation in failure unit test"
            .catch (err) ->
                throw err if !err instanceof Error || err.message != "no key found"
                done()
            .catch done

        it "Should dynamically load key if key is not found", (done) ->
            payload = test: "XYZZY"

            k1 = null
            testLoaderKeySet = sampleKeySet
            t = new JWKS loader: testLoader
            t.getKeyAsync kid: "testKey1"
            .then (key) ->
                k1 = key
                t.signAsync key, JSON.stringify payload
            .then (rv) ->
                t.removeKeyAsync k1
                .then () ->
                    # This should now not find the key, refresh, and then find the key
                    t.verifySignatureAsync rv
            .then (rv) -> done()
            .catch done

        it "Should not dynamically load key if doNotReloadOnMissingKey is set", (done) ->
            payload = test: "XYZZY"

            k1 = null
            testLoaderKeySet = sampleKeySet
            t = new JWKS doNotReloadOnMissingKey: true, loader: testLoader
            t.getKeyAsync kid: "testKey1"
            .then (key) ->
                k1 = key
                t.signAsync key, JSON.stringify payload
            .then (rv) ->
                t.removeKeyAsync k1
                .then () ->
                    # This should now not find the key, not refresh, and therfore not find the key
                    t.verifySignatureAsync rv
            .then (rv) -> throw new Error "Unexpected signature validation in failure unit test"
            .catch (err) ->
                throw err if !err instanceof Error || err.message != "no key found"
                done()
            .catch done

    describe "Encryption", () ->
        it "Should round-trip", (done) ->
            payload = test: "XYZZY"

            t = new JWKS jwks: sampleKeySet
            t.getKeyAsync kid: "testKey1"
            .then (key) ->
                t.encryptAsync key, JSON.stringify payload
                .then (rv) ->
                    expect(rv).to.be.ok
                    t.decryptAsync rv
                .then (rv) ->
                    expect(rv).to.be.ok
                    expect(rv.key.kid).to.equal("testKey1")
                    expect(rv.header.alg).to.equal("ECDH-ES")
                    expect(rv.header.enc).to.equal("A128CBC-HS256")
                    t2 = JSON.parse rv.plaintext.toString "utf8"
                    expect(t2).to.deep.equal(payload)

            .then () -> done()
            .catch done

        it "Should round-trip (with key search)", (done) ->
            payload = test: "XYZZY"

            t = new JWKS jwks: sampleKeySet
            t.encryptAsync { kid: "testKey1" }, JSON.stringify payload
            .then (rv) ->
                expect(rv).to.be.ok
                t.decryptAsync rv
            .then (rv) ->
                expect(rv).to.be.ok
                expect(rv.key.kid).to.equal("testKey1")
                expect(rv.header.alg).to.equal("ECDH-ES")
                expect(rv.header.enc).to.equal("A128CBC-HS256")
                t2 = JSON.parse rv.plaintext.toString "utf8"
                expect(t2).to.deep.equal(payload)
            .then () -> done()
            .catch done

        it "Should fail if no key is found", (done) ->
            payload = test: "XYZZY"

            t = new JWKS jwks: sampleKeySet
            t.encryptAsync { kid: "testKey99999" }, JSON.stringify payload
            .then () -> done new Error "Unexpected encryption success in failure unit test"
            .catch (err) ->
                if err.message == "No encryption key found" then done()
                else done err

        it "Should throw error if key is not found", (done) ->
            payload = test: "XYZZY"

            k1 = null
            t = new JWKS jwks: sampleKeySet
            t.getKeyAsync kid: "testKey1"
            .then (key) ->
                k1 = key
                t.encryptAsync key, JSON.stringify payload
            .then (rv) ->
                t.removeKeyAsync k1
                .then () -> t.decryptAsync rv
            .then (rv) -> throw new Error "Unexpected decryption success in failure unit test"
            .catch (err) ->
                throw err if !err instanceof Error || err.message != "no key found"
                done()
            .catch done

        it "Should dynamically load key if key is not found", (done) ->
            payload = test: "XYZZY"

            k1 = null
            testLoaderKeySet = sampleKeySet
            t = new JWKS loader: testLoader
            t.getKeyAsync kid: "testKey1"
            .then (key) ->
                k1 = key
                t.encryptAsync key, JSON.stringify payload
            .then (rv) ->
                t.removeKeyAsync k1
                .then () ->
                    # This should now not find the key, refresh, and then find the key
                    t.decryptAsync rv
            .then (rv) -> done()
            .catch done

        it "Should not dynamically load key if doNotReloadOnMissingKey is set", (done) ->
            payload = test: "XYZZY"

            k1 = null
            testLoaderKeySet = sampleKeySet
            t = new JWKS doNotReloadOnMissingKey: true, loader: testLoader
            t.getKeyAsync kid: "testKey1"
            .then (key) ->
                k1 = key
                t.encryptAsync key, JSON.stringify payload
            .then (rv) ->
                t.removeKeyAsync k1
                .then () ->
                    # This should now not find the key, not refresh, and therfore not find the key
                    t.decryptAsync rv
            .then (rv) -> throw new Error "Unexpected decrption success in failure unit test"
            .catch (err) ->
                throw err if !err instanceof Error || err.message != "no key found"
                done()
            .catch done
