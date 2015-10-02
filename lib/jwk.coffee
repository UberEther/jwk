events = require "events"
Promise = require "bluebird"
ms = require "ms"
_request = require "request"
_jose = require "node-jose"

Promise.promisifyAll _request

toMillis = (x) -> typeof x == "number" ? x : ms(x)

class JWK extends events.EventEmitter
    constructor: (options = {}) ->
        @clear()
        @changeJwkSetUrl options.jwkSetUrl

        @request = options.request || JWK.request.defaults options.requestDefaults
        @refreshDuration = toMillis options.refreshDuration || "1d"
        @expireDuration = toMillis options.expireDuration || "7d"

        if @jwkSetUrl then @refreshAt = @expireAt = 0

    changeJwkSetUrl: (newUrl) ->
        return if newUrl == @jwkSetUrl
        oldUrl = @jwkSetUrl
        @jwkSetUrl = newUrl
        @refreshAt = @expireAt = if newUrl then Number.MAX_SAFE_INTEGER else 0
        @emit "urlChanged", newUrl, oldUrl

    clear: () ->
        @emit "beforeClear"

        @refreshAt = @expireAt = 0
        @lastModified = @etag = undefined
        @keystore = JWK.jose.JWK.createKeyStore()
        @rememberedKeys = []

        @emit "cleared"

    refreshIfNeededAsync: () ->
        now = Date.now()
        if @refreshAt < now
            refreshNowAsync()
            if @expireAt < now then return @discoveryPromise
        return Promise.bind @, @keystore

    refreshNowAsync: () ->
        # Only valid if a URL is specified
        return Promise.bind @ if !@jwkSetUrl

        # Only 1 load at a time...
        if @refreshPromise then return @refreshPromise

        promise = @refreshPromise = Promise.bind @
        .then () ->
            reqOpts =
                url: @jwkSetUrl
                json: true

            # Set headers for conditional refreshes using etag or last-modified
            if @etag then reqOpts.headers["If-None-Match"] = @etag
            if @lastModified then reqOpts.headers["If-Modified-Since"] = @lastModified

            @emit "beforeRefresh", reqOpts
            @request.getAsync reqOpts
        .spread (res, raw) ->
            return if res.statusCode == 304 # Not modified...
            now = Date.now()
            importJwkSetAsync raw,
                refreshAt: now + @refreshDuration
                expireAt: now + @expireDuration
                etag: res.headers.etag
                lastModified: res.headers["last-modified"]

        .then () ->
            @emit "refreshed"
            return @keystore
        .finally () -> delete @refreshPromise
        .catch (err) -> if !@emit "refreshError", err then throw err

        return promise

    importJwkSetAsync: (jwkSet, meta) ->
        Promise.bind @
        .then () ->
            @emit "beforeJwkSetImport", jwkSet, meta

            # Validate and transform
            return JWK.jose.JWK.asKeyStore jwkSet
        .then (newKeyStore) ->
            # Update expirations, and actual keys
            @refreshAt = meta.refreshAt
            @expireAt = meta.expireAt
            @etag = meta.etag
            @lastModified = meta.lastModified

            @keystore = newKeyStore

            @emit "jwkSetImported"

    addKeyAsync: (key, remember = true) ->
        Promise.bind @
        .then () -> @keystore.add key
        .then (key) ->
            if remember then @rememberedKeys.push key
            emit "keyAdded", key, remember
            return key

        return key

    forgetKey: (oldKey) ->
        @rememberedKeys = @rememberedKeys.filter (x) -> return x != oldKey
        emit "keyForgotten", oldKey

    replaceKeyAsync: (oldKey, newKey) ->
        addKeyAsync newKey, @rememberedKeys.indexOf(oldKey) >= 0
        .then (rv) ->
            forgetKey oldKey
            return rv

    getKeyAsync: () -> # Arguments follow node-jose.get() - https://github.com/cisco/node-jose#retrieving-keys
        searchArgs = arguments
        refreshIfNeededAsync()
        .then () ->
            # Lookup and return the key
            rv = @keystore.get.apply @keystore, searchArgs
            return rv if rv

            # Not found?  Force an immediate refresh
            return Promise.bind @
            .then @refreshNow
            .then () -> @keystore.get.apply @keystore, searchArgs

    toJsonAsync: (exportPrivate) ->
        callArgs = arguments
        refreshIfNeededAsync()
        .then () -> @keystore.toJSON exportPrivate

    generateKeyAsync: (kty, size, props, remember = true) ->
        Promise.bind @
        .then () -> @keystore.generate kty, size, props
        .then (key) ->
            if remember then @rememberedKeys.push key
            return key

    verifySignatureAsync: (input, encoding) -> # https://github.com/cisco/node-jose#verifying-a-jws
        refreshIfNeededAsync()
        .then () ->
            JWK.jose.JWS.createVerify @keystore
            .verify input
        .catch (err) ->
            throw err if err != "key does not match"
            # Library rejects with "key does not match" if the key is not found...
            @refreshNow
            .then () ->
                JWK.jose.JWS.createVerify @keystore
                .verify input
            .catch (err) ->
                if err == "key does not match" then err = new Error "No matching signing key found"
                throw err

    signAsync: (key, content, options = {}) -> # https://github.com/cisco/node-jose#signing-content
        Promise.bind @
        .then () ->
            JWK.jose.JWS.createSign options, key
            .update content, options.encoding || "utf8"
            .final()

        # todo: Detect signature failure, reload keys, and retry

    encryptAsync: (key, content, options = {}) -> # https://github.com/cisco/node-jose#encrypting-content
        Promise.bind @
        .then () ->
            JWK.jose.JWE.createEncrypt options, key
            .update content, options.encoding || "utf8"
            .final()

    decryptAsync: (input) -> # https://github.com/cisco/node-jose#decrypting-a-jwe
        refreshIfNeededAsync()
        .then () ->
            JWK.jose.JWE.createDecrypt @keystore
            .verify input
        .catch (err) ->
            throw err if err != undefined
            # Library rejects with undefined if the key is not found...
            @refreshNow
            .then () ->
                JWK.jose.JWE.createDecrypt @keystore
                .verify input
            .catch (err) ->
                if err == undefined then err = new Error "No matching decryption key found"
                throw err

JWK.jose = _jose
JWK.request = _request

module.exports = JWK