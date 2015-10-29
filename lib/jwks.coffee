Promise = require "bluebird"
util = require "util"
_Loaders = require "auto-refresh-from-url"
_jose = require "node-jose"

class JWKS
    constructor: (options = {}) ->
        switch
            when options.jwks then @loader = new JWKS.Loaders.StaticLoader options.jwks
            when options.loader then @loader = options.loader
            when options.url
                urlOpts = util._extend {}, options.loaderOptions
                urlOpts.requestDefaults ||= {}
                if !urlOpts.requestDefaults.json? then urlOpts.requestDefaults.json = true
                urlOpts.requestDefaults.method ||= "GET"
                urlOpts.requestDefaults.headers ||= {}
                urlOpts.requestDefaults.headers.accept ||= "application/jwk-set+json, application/json, text/plain"
                t = new JWKS.Loaders.UrlLoader options.url, urlOpts
                @loader = new JWKS.Loaders.CachedLoader t, options.loaderOptions
            when options.file then @loader = new JWKS.Loaders.FileLoader options.file, options.loaderOptions
            else @loader = new JWKS.Loaders.StaticLoader keys: []

        @doNotReloadOnMissingKey = !!options.doNotReloadOnMissingKey
        @rememberedKeys = []

    loadAsync: (check) ->
        Promise.bind @
        .then () -> @loader.loadAsync check
        .then (rv) ->
            return if @jwks && !rv.loaded # Use cached value if we did not load
            Promise.bind @
            .then () -> JWKS.jose.JWK.asKeyStore rv.value
            .then (jwks) ->
                Promise.bind @, @rememberedKeys
                .map (key) -> jwks.add key
                .then () -> @jwks = jwks # Do not store till the very end...
        .then () -> return @jwks

    reset: (clearRememberedKeys) ->
        @jwks = null
        if clearRememberedKeys then @rememberedKeys = []

    addKeyAsync: (key, remember = true) ->
        @loadAsync()
        .then (keystore) -> keystore.add key
        .then (key) ->
            if remember then @rememberedKeys.push key
            return key

    removeKeyAsync: (oldKey) ->
        @loadAsync()
        .then (keystore) ->
            @rememberedKeys = @rememberedKeys.filter (x) -> return x != oldKey
            keystore.remove oldKey

    replaceKeyAsync: (oldKey, newKey) ->
        @loadAsync()
        .then (keystore) ->
            Promise.bind @
            .then () -> keystore.add newKey
            .then (newKey) ->
                oldLen = @rememberedKeys.length
                @rememberedKeys = @rememberedKeys.filter (x) -> return x != oldKey
                if oldLen != @rememberedKeys.length then @rememberedKeys.push newKey
                keystore.remove oldKey
                return newKey

    getKeyAsync: () -> # Arguments follow node-jose.get() - https://github.com/cisco/node-jose#retrieving-keys
        searchArgs = arguments

        @loadAsync()
        .then (keystore) ->
            # If you pass a key in, just return a promise for that key
            # But do after the refresh - the caller might be relying on that...
            if searchArgs.length == 1 && JWKS.jose.JWK.isKey searchArgs[0]
                return searchArgs[0]

            # Lookup and return the key
            rv = keystore.get.apply keystore, searchArgs
            return rv if rv || @doNotReloadOnMissingKey

            # Not found?  Force an immediate refresh
            return Promise.bind @, true
            .then @loadAsync
            .then (newKeystore) ->
                return rv if newKeystore == keystore
                newKeystore.get.apply newKeystore, searchArgs

    allKeysAsync: () -> # Arguments follow node-jose.get() - https://github.com/cisco/node-jose#retrieving-keys
        searchArgs = arguments
        @loadAsync()
        .then (keystore) ->
            # Lookup and return the key
            rv = keystore.all.apply keystore, searchArgs
            return rv if rv.length || @doNotReloadOnMissingKey

            # Not found?  Force an immediate refresh
            return Promise.bind @, true
            .then @loadAsync
            .then (newKeystore) ->
                return rv if newKeystore == keystore
                newKeystore.all.apply newKeystore, searchArgs

    toJsonAsync: (exportPrivate) ->
        callArgs = arguments
        @loadAsync()
        .then (keystore) -> keystore.toJSON exportPrivate

    generateKeyAsync: (kty, size, props, remember = true) ->
        @loadAsync()
        .then (keystore) -> keystore.generate kty, size, props
        .then (key) ->
            if remember then @rememberedKeys.push key
            return key

    verifySignatureAsync: (input, encoding) -> # https://github.com/cisco/node-jose#verifying-a-jws
        @loadAsync()
        .then (keystore) ->
            Promise.bind @
            .then () ->
                JWKS.jose.JWS.createVerify keystore
                .verify input
            .catch (err) ->
                throw err if err.message != "no key found" || @doNotReloadOnMissingKey
                # Library rejects with "key does not match" if the key is not found...
                @loadAsync true
                .then (newKeystore) ->
                    if newKeystore == keystore then throw err
                    JWKS.jose.JWS.createVerify newKeystore
                    .verify input

    signAsync: (key, content, options = {}) -> # https://github.com/cisco/node-jose#signing-content
        options.encoding ||= "utf8"
        options.format ||= "compact"
        @getKeyAsync key
        .then (key) ->
            if !key then throw new Error "No signing key found"
            JWKS.jose.JWS.createSign options, key
            .update content, options.encoding
            .final()

    encryptAsync: (key, content, options = {}) -> # https://github.com/cisco/node-jose#encrypting-content
        options.encoding ||= "utf8"
        options.format ||= "compact"
        @getKeyAsync key
        .then (key) ->
            if !key then throw new Error "No encryption key found"
            JWKS.jose.JWE.createEncrypt options, key
            .update content, options.encoding
            .final()

    decryptAsync: (input) -> # https://github.com/cisco/node-jose#decrypting-a-jwe
        @loadAsync()
        .then (keystore) ->
            Promise.bind @
            .then () ->
                JWKS.jose.JWE.createDecrypt keystore
                .decrypt input
            .catch (err) ->
                throw err if err.message != "no key found" || @doNotReloadOnMissingKey
                # Library rejects with undefined if the key is not found...
                @loadAsync true
                .then (newKeystore) ->
                    if newKeystore == keystore then throw err
                    JWKS.jose.JWE.createDecrypt newKeystore
                    .decrypt input

JWKS.jose = _jose
JWKS.Loaders = _Loaders

module.exports = JWKS