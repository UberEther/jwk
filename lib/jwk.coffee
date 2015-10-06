Promise = require "bluebird"
AutoRefresh = require "auto-refresh-from-url"
_jose = require "node-jose"

class JWK extends AutoRefresh
    constructor: (options = {}) ->
        super options
        @doNotReloadOnMissingKey = !!options.doNotReloadOnMissingKey
        @rememberedKeys = []

    prepareRefreshRequest: () ->
        if @useManualJwk then return
        super

    processUrlData: (res, raw, oldPayload) -> # May return value or promise
        # Use super implementation to validate status codes
        raw = super

        if !raw
            if @manualJwk
                raw = @manualJwk
                @manualJwk = null
            else return oldPayload || JWK.jose.JWK.createKeyStore()

        Promise.bind @
        .then () -> JWK.jose.JWK.asKeyStore raw
        .then (newKeystore) ->
            Promise.bind @, @rememberedKeys
            .map (key) -> newKeystore.add key
            .return newKeystore

    manualLoadJwkAsync: (jwk) ->
        @useManualJwk = !!jwk
        @manualJwk = jwk

        # Force an immediate reload - if a refresh is in progress then we must wait for it
        if @refreshPromise then return @refreshPromise.then () -> @refreshNowAsync true
        else return @refreshNowAsync true

    addKeyAsync: (key, remember = true) ->
        @refreshIfNeededAsync()
        .then (keystore) -> keystore.add key
        .then (key) ->
            if remember then @rememberedKeys.push key
            return key

    removeKeyAsync: (oldKey) ->
        @refreshIfNeededAsync()
        .then (keystore) ->
            @rememberedKeys = @rememberedKeys.filter (x) -> return x != oldKey
            keystore.remove oldKey

    replaceKeyAsync: (oldKey, newKey) ->
        @refreshIfNeededAsync()
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
        @refreshIfNeededAsync()
        .then (keystore) ->
            # Lookup and return the key
            rv = keystore.get.apply keystore, searchArgs
            return rv if rv || @doNotReloadOnMissingKey

            # Not found?  Force an immediate refresh
            return Promise.bind @
            .then @refreshNowAsync
            .then (newKeystore) ->
                return rv if newKeystore == keystore
                newKeystore.get.apply newKeystore, searchArgs

    allKeysAsync: () -> # Arguments follow node-jose.get() - https://github.com/cisco/node-jose#retrieving-keys
        searchArgs = arguments
        @refreshIfNeededAsync()
        .then (keystore) ->
            # Lookup and return the key
            rv = keystore.all.apply keystore, searchArgs
            return rv if rv.length || @doNotReloadOnMissingKey

            # Not found?  Force an immediate refresh
            return Promise.bind @
            .then @refreshNowAsync
            .then (newKeystore) ->
                return rv if newKeystore == keystore
                newKeystore.all.apply newKeystore, searchArgs

    toJsonAsync: (exportPrivate) ->
        callArgs = arguments
        @refreshIfNeededAsync()
        .then (keystore) -> keystore.toJSON exportPrivate

    generateKeyAsync: (kty, size, props, remember = true) ->
        @refreshIfNeededAsync()
        .then (keystore) -> keystore.generate kty, size, props
        .then (key) ->
            if remember then @rememberedKeys.push key
            return key

    verifySignatureAsync: (input, encoding) -> # https://github.com/cisco/node-jose#verifying-a-jws
        @refreshIfNeededAsync()
        .then (keystore) ->
            Promise.bind @
            .then () ->
                JWK.jose.JWS.createVerify keystore
                .verify input
            .catch (err) ->
                throw err if err.message != "no key found" || @doNotReloadOnMissingKey
                # Library rejects with "key does not match" if the key is not found...
                @refreshNowAsync()
                .then (newKeystore) ->
                    if newKeystore == keystore then throw err
                    JWK.jose.JWS.createVerify newKeystore
                    .verify input

    signAsync: (key, content, options = {}) -> # https://github.com/cisco/node-jose#signing-content
        options.encoding ||= "utf8"
        options.format ||= "compact"
        Promise.bind @
        .then () ->
            JWK.jose.JWS.createSign options, key
            .update content, options.encoding
            .final()

        # todo: Detect signature failure, reload keys, and retry

    encryptAsync: (key, content, options = {}) -> # https://github.com/cisco/node-jose#encrypting-content
        options.encoding ||= "utf8"
        options.format ||= "compact"
        Promise.bind @
        .then () ->
            JWK.jose.JWE.createEncrypt options, key
            .update content, options.encoding
            .final()

    decryptAsync: (input) -> # https://github.com/cisco/node-jose#decrypting-a-jwe
        @refreshIfNeededAsync()
        .then (keystore) ->
            Promise.bind @
            .then () ->
                JWK.jose.JWE.createDecrypt keystore
                .decrypt input
            .catch (err) ->
                throw err if err.message != "no key found" || @doNotReloadOnMissingKey
                # Library rejects with undefined if the key is not found...
                @refreshNowAsync()
                .then (newKeystore) ->
                    if newKeystore == keystore then throw err
                    JWK.jose.JWE.createDecrypt newKeystore
                    .decrypt input

JWK.jose = _jose

module.exports = JWK