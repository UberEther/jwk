expect = require("chai").expect
JWKS = require "../lib"
path = require "path"
Promise = require "bluebird"
jose = JWKS.jose

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

testLoaderKeySet = null
testLoader =
    loadAsync: (check) -> return Promise.resolve value: testLoaderKeySet, loaded: check
    reset: () ->

verifySampleKeySet = (keyset) ->
    keys = keyset.all()
    expect(keys.length).to.equal(1)
    key = keys[0]

    expect(jose.JWK.isKey(key)).to.be.true
    expect(key.toJSON(true)).to.deep.equals(sampleKey1)

describe "JWKS", () ->
    it "should construct with correct defaults", () ->
        t = new JWKS
        expect(t.rememberedKeys).to.deep.equal([])
        expect(t.doNotReloadOnMissingKey).to.equal(false)

    it "should construct with correct overrides", () ->
        t = new JWKS
            doNotReloadOnMissingKey: true

        expect(t.rememberedKeys).to.deep.equal([])
        expect(t.doNotReloadOnMissingKey).to.equal(true)

    it "should construct with a url", () ->
        t = new JWKS url: "https://jwks.example.com/foo"
        # todo: More complete verification here
        expect(t.loader.childLoader.url).to.equal("https://jwks.example.com/foo")
        
    it "should construct with a file", () ->
        t = new JWKS file: "foo.txt"
        # todo: More complete verification here
        expect(t.loader.file).to.equal(path.resolve("foo.txt"))

    it "should allow us to override json to false for URLs (processor required)", () ->
        t = new JWKS url: "https://jwks.example.com/foo", loaderOptions: requestDefaults: json: false
        # todo: More complete verification here
        expect(t.loader.childLoader.url).to.equal("https://jwks.example.com/foo")
        
    describe "Remembered Keys", () ->
        it "Should remember tagged keys", (done) ->
            testLoaderKeySet = keys: []
            t = new JWKS loader: testLoader
            t.addKeyAsync sampleKey2
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([key])

                keys = t.jwks.get kid: "testKey2"
                expect(keys).to.equal(key)
                expect(jose.JWK.isKey(key)).to.be.true
                expect(key.toJSON(true)).to.deep.equals(sampleKey2)

                testLoaderKeySet = sampleKeySet
                t.loadAsync true
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

        it "Should forget remembered keys on reset if requested", (done) ->
            t = new JWKS
            t.loadAsync()
            .then () -> t.addKeyAsync sampleKey2
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([key])
                t.reset(true)
                expect(t.jwks).to.equal(null)
                expect(t.rememberedKeys).to.deep.equal([])
            .then () -> done()
            .catch done

        it "Should not forget remembered keys on reset if not requested", (done) ->
            t = new JWKS
            t.loadAsync()
            .then () -> t.addKeyAsync sampleKey2
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([key])
                t.reset()
                expect(t.jwks).to.equal(null)
                expect(t.rememberedKeys).to.deep.equal([key])
            .then () -> done()
            .catch done

        it "Should remember not remember untagged keys", (done) ->
            testLoaderKeySet = keys: []
            t = new JWKS loader: testLoader
            t.addKeyAsync sampleKey2, false
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([])

                newKey = t.jwks.get kid: "testKey2"
                expect(newKey).to.be.ok
                expect(jose.JWK.isKey(newKey)).to.be.true
                expect(newKey.toJSON(true)).to.deep.equals(sampleKey2)

                testLoaderKeySet = sampleKeySet
                t.loadAsync true
                .then (keystore) -> verifySampleKeySet keystore
            .then () -> done()
            .catch done

        it "Should not remember removed keys", (done) ->
            testLoaderKeySet = keys: []
            t = new JWKS loader: testLoader
            t.addKeyAsync sampleKey2
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([key])

                newKey = t.jwks.get kid: "testKey2"
                expect(newKey).to.be.ok
                expect(jose.JWK.isKey(newKey)).to.be.true
                expect(newKey.toJSON(true)).to.deep.equals(sampleKey2)

                t.removeKeyAsync key
            .then () ->
                expect(t.jwks.all().length).to.equal(0)
                testLoaderKeySet = sampleKeySet
                t.loadAsync true
            .then (keystore) -> verifySampleKeySet keystore
            .then () -> done()
            .catch done

        it "Should keep remember value during replace (remember=true)", (done) ->
            t = new JWKS
            t.addKeyAsync sampleKey2
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([key])

                newKey = t.jwks.get kid: "testKey2"
                expect(newKey).to.be.ok
                expect(jose.JWK.isKey(newKey)).to.be.true
                expect(newKey.toJSON(true)).to.deep.equals(sampleKey2)

                t.replaceKeyAsync key, sampleKey3
            .then (key) ->
                newKey = t.jwks.get kid: "testKey3"
                expect(newKey).to.be.ok
                expect(jose.JWK.isKey(newKey)).to.be.true
                expect(newKey.toJSON(true)).to.deep.equals(sampleKey3)

                expect(t.rememberedKeys).to.deep.equal([key])
            .then () -> done()
            .catch done

        it "Should keep remember value during replace (remember=false)", (done) ->
            t = new JWKS
            t.addKeyAsync sampleKey2, false
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([])

                newKey = t.jwks.get kid: "testKey2"
                expect(newKey).to.be.ok
                expect(jose.JWK.isKey(newKey)).to.be.true
                expect(newKey.toJSON(true)).to.deep.equals(sampleKey2)

                t.replaceKeyAsync key, sampleKey3
            .then (key) ->
                expect(t.rememberedKeys).to.deep.equal([])

                newKey = t.jwks.get kid: "testKey3"
                expect(newKey).to.be.ok
                expect(jose.JWK.isKey(newKey)).to.be.true
                expect(newKey.toJSON(true)).to.deep.equals(sampleKey3)
            .then () -> done()
            .catch done

    describe "Retrieve Key", () ->
        it "Should be able to get a key", (done) ->
            t = new JWKS
            t.addKeyAsync sampleKey2
            .then () -> t.getKeyAsync kid: "testKey2"
            .then (key) ->
                expect(key).to.be.ok
                expect(jose.JWK.isKey(key)).to.be.true
                expect(key.toJSON(true)).to.deep.equals(sampleKey2)
            .then () -> done()
            .catch done

        it "Should return falsey if key not found", (done) ->
            t = new JWKS
            t.addKeyAsync sampleKey2
            .then () -> t.getKeyAsync kid: "testKey999999"
            .then (key) -> expect(key).to.not.be.ok
            .then () -> done()
            .catch done

        it "Should attempt to reload keystore if the key is not found", (done) ->
            testLoaderKeySet = keys: []
            t = new JWKS loader: testLoader
            t.loadAsync()
            .then () ->
                testLoaderKeySet = sampleKeySet
                # This should now not find the key, refresh, and then find the key
                t.getKeyAsync kid: "testKey1"
            .then (key) ->
                expect(key).to.be.ok
                expect(jose.JWK.isKey(key)).to.be.true
                expect(key.toJSON(true)).to.deep.equals(sampleKey1)
            .then () -> done()
            .catch done

        it "Should NOT attempt to reload keystore if doNotReloadOnMissingKey is set", (done) ->
            testLoaderKeySet = keys: []
            t = new JWKS loader: testLoader, doNotReloadOnMissingKey: true
            t.loadAsync()
            .then () ->
                testLoaderKeySet = sampleKeySet
                # This should now not find the key, refresh, and then find the key
                t.getKeyAsync kid: "testKey1"
            .then (key) -> expect(key).to.not.be.ok
            .then () -> done()
            .catch done

    describe "Retrieve All Matching Key", () ->
        it "Should be able to get matching key", (done) ->
            t = new JWKS
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
            testLoaderKeySet = keys: []
            t = new JWKS loader: testLoader
            t.loadAsync()
            .then () ->
                testLoaderKeySet = sampleKeySet
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
            testLoaderKeySet = keys: []
            t = new JWKS loader: testLoader, doNotReloadOnMissingKey: true
            t.loadAsync()
            .then () ->
                testLoaderKeySet = sampleKeySet
                # This should now not find the key, refresh, and then find the key
                t.allKeysAsync kid: "testKey1"
            .then (keys) -> expect(keys).to.deep.equal([])
            .then () -> done()
            .catch done

    it "Should generate remembered keys", (done) ->
        t = new JWKS
        t.generateKeyAsync "oct", 256, kid: "testGen1"
        .then (key) ->
            t.getKeyAsync kid: "testGen1"
            .then (key2) ->
                expect(key2).to.equal(key)
                expect(t.rememberedKeys).to.deep.equal([key])
        .then () -> done()
        .catch done

    it "Should generate non-remembered keys", (done) ->
        t = new JWKS
        t.generateKeyAsync "oct", 256, kid: "testGen1", false
        .then (key) ->
            t.getKeyAsync kid: "testGen1"
            .then (key2) ->
                expect(key2).to.equal(key)
                expect(t.rememberedKeys).to.deep.equal([])
        .then () -> done()
        .catch done

    it "Should export to JSON", (done) ->
        t = new JWKS jwks: sampleKeySet
        t.toJsonAsync true
        .then (rv) -> expect(rv).to.deep.equal(sampleKeySet)
        .then () -> done()
        .catch done
