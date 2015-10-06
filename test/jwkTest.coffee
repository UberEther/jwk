http = require "http"
expect = require("chai").expect
JWK = require "../lib"
Promise = require "bluebird"
jose = JWK.jose

sampleKey1 =
    kty: "EC"
    kid: "testKey1"
    crv: "P-256"
    x: "uiOfViX69jYwnygrkPkuM0XqUlvW65WEs_7rgT3eaak"
    y: "v8S-ifVFkNLoe1TSUrNFQVj6jRbK1L8V-eZa-ngsZLM"
    d: "dI5TRpZrVLpTr_xxYK-n8FgTBpe5Uer-8QgHu5gx9Ds"
sampleKey2 =
    kty: "oct"
    kid: "testKey2"
    use: "sig"
    alg: "HS256"
    k: "l3nZEgZCeX8XRwJdWyK3rGB8qwjhdY8vOkbIvh4lxTuMao9Y_--hdg"
sampleKey3 =
    kty: "oct"
    kid: "testKey3"
    use: "enc"
    alg: "HS256"
    k: "l3nZEgZCeX8XRwJdWyK3rGB8qwjhdY8vOkbIvh4lxTuMao9Y_--hdg"
sampleKeySet = keys: [ sampleKey1 ]

verifySampleKeySet = (keyset) ->
    keys = keyset.all()
    expect(keys.length).to.equal(1)
    key = keys[0]

    expect(jose.JWK.isKey(key)).to.be.true
    expect(key.toJSON(true)).to.deep.equals(sampleKey1)

describe "JWK", () ->
    it "should construct with correct defaults", () ->
        t = new JWK

        expect(t.rememberedKeys).to.deep.equal([])
        expect(t.doNotReloadOnMissingKey).to.equal(false)

    it "should construct with correct overrides", () ->
        t = new JWK
            doNotReloadOnMissingKey: true

        expect(t.rememberedKeys).to.deep.equal([])
        expect(t.doNotReloadOnMissingKey).to.equal(true)

    describe "prepareRefreshRequest", () ->
        it "should use default request unless useManualJwk is set", () ->
            t = new JWK

            rv = t.prepareRefreshRequest()
            expect(rv).to.be.ok

            t.useManualJwk = true
            rv = t.prepareRefreshRequest()
            expect(rv).to.not.be.ok

    describe "processUrlData", () ->
        it "should return an empty jwkSet if there is no jwk to load", (done) ->
            t = new JWK

            Promise.try () -> t.processUrlData null, null, null
            .then (rv) ->
                expect(rv).to.be.ok
                expect(rv.all().length).to.equal(0)
            .then () -> done()
            .catch done

        it "should load the manualJwk if one is waiting", (done) ->
            t = new JWK
            t.manualJwk = JSON.stringify sampleKeySet

            Promise.try () -> t.processUrlData null, null, null
            .then (rv) ->
                expect(rv).to.be.ok
                verifySampleKeySet rv
            .then () -> done()
            .catch done

        it "should load the data provided", (done) ->
            t = new JWK

            Promise.try () -> t.processUrlData null, sampleKeySet, null
            .then (rv) ->
                expect(rv).to.be.ok
                verifySampleKeySet rv
            .then () -> done()
            .catch done

    describe "Manual load", () ->
        it "Should manually load files", (done) ->
            t = new JWK
            t.manualLoadJwkAsync sampleKeySet
            .then (keystore) -> verifySampleKeySet keystore
            .then () -> done()
            .catch done

        it "Should wait for pending refreshes to complete", (done) ->
            t = new JWK
            t.manualLoadJwkAsync null
            t.manualLoadJwkAsync sampleKeySet
            .then (keystore) -> verifySampleKeySet keystore
            .then () -> done()
            .catch done

    describe "Remembered Keys", () ->
        it "Should remember tagged keys", (done) ->
            t = new JWK
            t.addKeyAsync sampleKey2
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([key])

                keys = t.payload.get kid: "testKey2"
                expect(keys).to.equal(key)
                expect(jose.JWK.isKey(key)).to.be.true
                expect(key.toJSON(true)).to.deep.equals(sampleKey2)

                t.manualLoadJwkAsync sampleKeySet
                .then (keystore) ->
                    keys = keystore.all()
                    expect(keys.length).to.equal(2)

                    newKey = keystore.get kid: "testKey2"
                    expect(newKey).to.be.ok
                    expect(jose.JWK.isKey(newKey)).to.be.true
                    expect(newKey.toJSON(true)).to.deep.equals(sampleKey2)

                    newKey = keystore.get kid: "testKey1"
                    expect(newKey).to.be.ok
                    expect(jose.JWK.isKey(newKey)).to.be.true
                    expect(newKey.toJSON(true)).to.deep.equals(sampleKey1)
            .then () -> done()
            .catch done

        it "Should remember not remember untagged keys", (done) ->
            t = new JWK
            t.addKeyAsync sampleKey2, false
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([])

                newKey = t.payload.get kid: "testKey2"
                expect(newKey).to.be.ok
                expect(jose.JWK.isKey(newKey)).to.be.true
                expect(newKey.toJSON(true)).to.deep.equals(sampleKey2)

                t.manualLoadJwkAsync sampleKeySet
                .then (keystore) -> verifySampleKeySet keystore
            .then () -> done()
            .catch done

        it "Should not remember removed keys", (done) ->
            t = new JWK
            t.addKeyAsync sampleKey2
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([key])

                newKey = t.payload.get kid: "testKey2"
                expect(newKey).to.be.ok
                expect(jose.JWK.isKey(newKey)).to.be.true
                expect(newKey.toJSON(true)).to.deep.equals(sampleKey2)

                t.removeKeyAsync key
            .then () ->
                expect(t.payload.all().length).to.equal(0)
                t.manualLoadJwkAsync sampleKeySet
            .then (keystore) -> verifySampleKeySet keystore
            .then () -> done()
            .catch done

        it "Should keep remember value during replace (remember=true)", (done) ->
            t = new JWK
            t.addKeyAsync sampleKey2
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([key])

                newKey = t.payload.get kid: "testKey2"
                expect(newKey).to.be.ok
                expect(jose.JWK.isKey(newKey)).to.be.true
                expect(newKey.toJSON(true)).to.deep.equals(sampleKey2)

                t.replaceKeyAsync key, sampleKey3
            .then (key) ->
                newKey = t.payload.get kid: "testKey3"
                expect(newKey).to.be.ok
                expect(jose.JWK.isKey(newKey)).to.be.true
                expect(newKey.toJSON(true)).to.deep.equals(sampleKey3)

                expect(t.rememberedKeys).to.deep.equal([key])
            .then () -> done()
            .catch done

        it "Should keep remember value during replace (remember=false)", (done) ->
            t = new JWK
            t.addKeyAsync sampleKey2, false
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([])

                newKey = t.payload.get kid: "testKey2"
                expect(newKey).to.be.ok
                expect(jose.JWK.isKey(newKey)).to.be.true
                expect(newKey.toJSON(true)).to.deep.equals(sampleKey2)

                t.replaceKeyAsync key, sampleKey3
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([])

                newKey = t.payload.get kid: "testKey3"
                expect(newKey).to.be.ok
                expect(jose.JWK.isKey(newKey)).to.be.true
                expect(newKey.toJSON(true)).to.deep.equals(sampleKey3)
            .then () -> done()
            .catch done

    describe "Retrieve Key", () ->
        it "Should be able to get a key", (done) ->
            t = new JWK
            t.addKeyAsync sampleKey2
            .then () -> t.getKeyAsync kid: "testKey2"
            .then (key) ->
                expect(key).to.be.ok
                expect(jose.JWK.isKey(key)).to.be.true
                expect(key.toJSON(true)).to.deep.equals(sampleKey2)
            .then () -> done()
            .catch done

        it "Should return falsey if key not found", (done) ->
            t = new JWK
            t.addKeyAsync sampleKey2
            .then () -> t.getKeyAsync kid: "testKey999999"
            .then (key) -> expect(key).to.not.be.ok
            .then () -> done()
            .catch done

        it "Should attempt to reload keystore if the key is not found", (done) ->
            t = new JWK
            t.refreshIfNeededAsync()
            .then () ->
                t.doNotRefreshBefore = 0
                t.manualJwk = sampleKeySet
                # This should now not find the key, refresh, and then find the key
                t.getKeyAsync kid: "testKey1"
            .then (key) ->
                expect(key).to.be.ok
                expect(jose.JWK.isKey(key)).to.be.true
                expect(key.toJSON(true)).to.deep.equals(sampleKey1)
            .then () -> done()
            .catch done

        it "Should NOT attempt to reload keystore if doNotReloadOnMissingKey is set", (done) ->
            t = new JWK doNotReloadOnMissingKey: true
            t.refreshIfNeededAsync()
            .then () ->
                t.doNotRefreshBefore = 0
                t.manualJwk = sampleKeySet
                # This should now not find the key, refresh, and then find the key
                t.getKeyAsync kid: "testKey1"
            .then (key) -> expect(key).to.not.be.ok
            .then () -> done()
            .catch done

    describe "Retrieve All Matching Key", () ->
        it "Should be able to get matching key", (done) ->
            t = new JWK
            k1 = k2 = null
            t.addKeyAsync sampleKey2
            .then (rv) ->
                k1 = rv
                t.addKeyAsync sampleKey3
            .then (rv) ->
                k2 = rv
                t.allKeysAsync kid: "testKey2"
            .then (keys) ->
                expect(keys).to.deep.equals([k1])
                t.allKeysAsync kty: "oct"
            .then (keys) ->
                expect(keys).to.deep.equals([k1, k2])
                t.allKeysAsync kid: "testKey999999"
            .then (keys) ->
                expect(keys).to.deep.equals([])
            .then () -> done()
            .catch done

        it "Should attempt to reload keystore if the key is not found", (done) ->
            t = new JWK
            t.refreshIfNeededAsync()
            .then () ->
                t.doNotRefreshBefore = 0
                t.manualJwk = sampleKeySet
                # This should now not find the key, refresh, and then find the key
                t.allKeysAsync kid: "testKey1"
            .then (keys) ->
                expect(keys).to.be.ok
                expect(keys.length).to.equal(1)
                expect(jose.JWK.isKey(keys[0])).to.be.true
                expect(keys[0].toJSON(true)).to.deep.equals(sampleKey1)
            .then () -> done()
            .catch done

        it "Should NOT attempt to reload keystore if doNotReloadOnMissingKey is set", (done) ->
            t = new JWK doNotReloadOnMissingKey: true
            t.refreshIfNeededAsync()
            .then () ->
                t.doNotRefreshBefore = 0
                t.manualJwk = sampleKeySet
                # This should now not find the key, refresh, and then find the key
                t.allKeysAsync kid: "testKey1"
            .then (keys) -> expect(keys).to.deep.equal([])
            .then () -> done()
            .catch done

    it "Should generate remembered keys", (done) ->
        t = new JWK
        t.generateKeyAsync "oct", 256, kid: "testGen1"
        .then (key) ->
            t.getKeyAsync kid: "testGen1"
            .then (key2) ->
                expect(key2).to.equal(key)
                expect(t.rememberedKeys).to.deep.equal([key])
        .then () -> done()
        .catch done

    it "Should generate non-remembered keys", (done) ->
        t = new JWK
        t.generateKeyAsync "oct", 256, kid: "testGen1", false
        .then (key) ->
            t.getKeyAsync kid: "testGen1"
            .then (key2) ->
                expect(key2).to.equal(key)
                expect(t.rememberedKeys).to.deep.equal([])
        .then () -> done()
        .catch done

    it "Should export to JSON", (done) ->
        t = new JWK
        t.manualLoadJwkAsync sampleKeySet
        .then () -> t.toJsonAsync true
        .then (rv) -> expect(rv).to.deep.equal(sampleKeySet)
        .then () -> done()
        .catch done

    describe "Signature helpers", () ->
        it "Should round-trip", (done) ->
            payload = test: "XYZZY"

            t = new JWK
            t.manualLoadJwkAsync sampleKeySet
            .then () -> t.getKeyAsync kid: "testKey1"
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

        it "Should throw error if key is not found", (done) ->
            payload = test: "XYZZY"

            k1 = null
            t = new JWK
            t.manualLoadJwkAsync sampleKeySet
            .then () -> t.getKeyAsync kid: "testKey1"
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
            t = new JWK
            t.generateKeyAsync "RSA", 1024, kid: "testKey1"
            .then () -> t.getKeyAsync kid: "testKey1"
            .then (key) ->
                k1 = key
                t.signAsync key, JSON.stringify payload
            .then (rv) ->
                t.removeKeyAsync k1
                .then () ->
                    t.doNotRefreshBefore = 0
                    t.manualJwk = keys: [ k1 ]
                    # This should now not find the key, refresh, and then find the key
                    t.verifySignatureAsync rv
            .then (rv) -> done()
            .catch done

        it "Should not dynamically load key if doNotReloadOnMissingKey is set", (done) ->
            payload = test: "XYZZY"

            k1 = null
            t = new JWK doNotReloadOnMissingKey: true
            t.generateKeyAsync "RSA", 1024, kid: "testKey1"
            .then () -> t.getKeyAsync kid: "testKey1"
            .then (key) ->
                k1 = key
                t.signAsync key, JSON.stringify payload
            .then (rv) ->
                t.removeKeyAsync k1
                .then () ->
                    t.doNotRefreshBefore = 0
                    t.manualJwk = keys: [ k1 ]
                    # This should now not find the key, refresh, and then find the key
                    t.verifySignatureAsync rv
            .then (rv) -> throw new Error "Unexpected signature validation in failure unit test"
            .catch (err) ->
                throw err if !err instanceof Error || err.message != "no key found"
                done()
            .catch done

    describe "Encryption helpers", () ->
        it "Should round-trip", (done) ->
            payload = test: "XYZZY"

            t = new JWK
            t.generateKeyAsync "RSA", 1024, kid: "testKey1"
            .then () -> t.getKeyAsync kid: "testKey1"
            .then (key) ->
                t.encryptAsync key, JSON.stringify payload
                .then (rv) ->
                    expect(rv).to.be.ok
                    t.decryptAsync rv
                .then (rv) ->
                    expect(rv).to.be.ok
                    expect(rv.key).to.equal(key)
                    expect(rv.header).to.deep.equal("alg": "RSA-OAEP", "enc": "A128CBC-HS256", kid: "testKey1")
                    t2 = JSON.parse rv.plaintext.toString "utf8"
                    expect(t2).to.deep.equal(payload)

            .then () -> done()
            .catch done

        it "Should throw error if key is not found", (done) ->
            payload = test: "XYZZY"

            k1 = null
            t = new JWK
            t.generateKeyAsync "RSA", 1024, kid: "testKey1"
            .then () -> t.getKeyAsync kid: "testKey1"
            .then (key) ->
                k1 = key
                t.encryptAsync key, JSON.stringify payload
            .then (rv) ->
                t.removeKeyAsync k1
                .then () -> t.decryptAsync rv
            .then (rv) -> throw new Error "Unexpected decrption success in failure unit test"
            .catch (err) ->
                throw err if !err instanceof Error || err.message != "no key found"
                done()
            .catch done

        it "Should dynamically load key if key is not found", (done) ->
            payload = test: "XYZZY"

            k1 = null
            t = new JWK
            t.generateKeyAsync "RSA", 1024, kid: "testKey1"
            .then () -> t.getKeyAsync kid: "testKey1"
            .then (key) ->
                k1 = key
                t.encryptAsync key, JSON.stringify payload
            .then (rv) ->
                t.removeKeyAsync k1
                .then () ->
                    t.doNotRefreshBefore = 0
                    t.manualJwk = keys: [ k1 ]
                    # This should now not find the key, refresh, and then find the key
                    t.decryptAsync rv
            .then (rv) -> done()
            .catch done

        it "Should not dynamically load key if doNotReloadOnMissingKey is set", (done) ->
            payload = test: "XYZZY"

            k1 = null
            t = new JWK doNotReloadOnMissingKey: true
            t.generateKeyAsync "RSA", 1024, kid: "testKey1"
            .then () -> t.getKeyAsync kid: "testKey1"
            .then (key) ->
                k1 = key
                t.encryptAsync key, JSON.stringify payload
            .then (rv) ->
                t.removeKeyAsync k1
                .then () ->
                    t.doNotRefreshBefore = 0
                    t.manualJwk = keys: [ k1 ]
                    # This should now not find the key, refresh, and then find the key
                    t.decryptAsync rv
            .then (rv) -> throw new Error "Unexpected decrption success in failure unit test"
            .catch (err) ->
                throw err if !err instanceof Error || err.message != "no key found"
                done()
            .catch done
