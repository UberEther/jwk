[![Build Status](https://travis-ci.org/UberEther/jwk.svg?branch=master)](https://travis-ci.org/UberEther/jwk)
[![NPM Status](https://badge.fury.io/js/uberether-jwk.svg)](http://badge.fury.io/js/uberether-jwk)

# TODO:
- [ ] Integrate dynamic unit tests that use the [jose-cookbook](https://github.com/ietf-jose/cookbook) data - while many of these are really node-jose's responsibility, it would be good for us to verify and enforce in our tests.
- [ ] Consider renaming package to uberether-jwks since it manages key sets and not individual keys
- [ ] Unit-test cleanup after migration to new loaders

# Overview

This library builds upon [node-jose](https://github.com/cisco/node-jose) and [auto-refresh-from-url](https://github.com/UberEther/auto-refresh-from-url) to allow for loading of JWK sets from a URL (with periodic or on-demand refresh) and performing JKA and JKS operations.

All asynchronous methods return Bluebird promises.  If you require callbacks, you can use the [Bluebird nodeify method](https://github.com/petkaantonov/bluebird/blob/master/API.md#nodeifyfunction-callback--object-options---promise).  For example: ```foo.somethingTharReturnsPromise().nodeify(callback);```

Keys are reloaded from the URL as per auto-refresh-from-url settings (which can be passed through via the constructor).  Additionally, keys are (by default) refreshed if a key is not found or no valid key is found for a signature or encryption operation.  

Keys may be manually added to the keyset also.  These keys can be optionally remembered on subsequent reloads.

Lastly, the library supports manually loading data instead of fetching it from a URL.


# Examples of use:

## Javascript:

```js
var JWK = require("uberether-jwk");
var jwk = new JWK({ urk: "http://jwk.example.com/foo" });

jwk.verifySignatureAsync("SignedInputString")
.then(function() { doStuffHere() })
.catch(function(err) { err.stack || err.message || err });

// Direct use of node-jose:
jwk.loadAsync()
.then(function(keystore) {
	return JWK.jose.JWE.createDecrypt(keystore).verify("xxxxx", "utf8");
});
```

## Coffeescript:
```coffeescript
JWK = require "uberether-jwk"
jwk = new JWK url: "http://jwk.example.com/foo"

jwk.verifySignatureAsync "SignedInputString"
.then () -> doStuffHere()
.catch (err) -> console.log err.stack || err.message || err

# Direct use of node-jose:
jwk.loadAsync()
.then (keystore) -> return JWK.jose.JWE.createDecrypt(keystore).verify("xxxxx", "utf8");
```

# API

## JWK Set Manager

A class that manages the key sets.  This is the main export for the library.

### JWKS.jose
The instance of Jose used by JWK.  It defaults to the copy loaded by the library using ```require("node-jose")``` but can be modified or replaced by the caller.

### new JWKS(options)

Constructs a new JWK set manager.

Options Available:
- doNotReloadOnMissingKey: Optional - if set to true, then the library will not try to refresh the JWK set when a key is not found

- Loader options (in priority order)
    - jwks: A static jwks JSON object to load the keys from
    - loader: An auto-refresh-from-url compatible loader to load from
    - url: URL to load keys from.  An auto-refresh-from-url CachedLoader wrapping a UrlLoader is constructed.  options.loaderOptions are passed on to both loader's constructors.  The following loader options are defaulted if not specifed:
    	- requestDefaults
    		- json: defaults to ```true``` if not specified.  If set false, you must provide a processor to transform the data into an object.
    		- method: defaults to ```"GET"```
    		- headers:
    			- accept: defaults to: ```"application/jwk-set+json, application/json, text/plain"```
    - file: A file to load keys from.  An auto-refresh-from-url FileLoader is constructed for this file.  options.loaderOptions is passed into the constructor.

### JWK.loadAsync(check)
Loads the jose JWKS object.  Check is passed onto the underlying loader to indicate if the source should be activly checked for updates.

### JWK.reset(forgetKeys)
Removes any cached data.  If forgetKeys is true, then remembered keys are all forgotten.

If a load is already in progress, the result of the load will be retained.

### JWK.addKeyAsync(key, remember = true)

Adds a key to the key set.
- key may be either a JWK JSON object OR a JWK.Key compatible object
- If remember is true, then the key will be readded whenever a new JWK set JSON is loaded

Returns a promise that resolves to the node-jose key object for the added key

### JWK.removeKeyAsync(key)

Removes the node-jose key specified from the keystore.

### JWK.replaceKeyAsync(oldKey, newKey)

Replaces the specified key with a new key.  Returns a promse that resolves to the new node-jose key.

### JWK.getKeyAsync()

Returns a promise that resolve to a key from the keystore.  Arguments are as per [node-jose.get](https://github.com/cisco/node-jose#retrieving-keys).  If multiple keys match, then only ONE key is returned.

If the key is not found, the keystore will refresh (unless doNotReloadOnMissingKey was specified).  If the key is still not found, undefined will be returned.

If the first argument is a node-jose key object, then this will resolve to the key passed in.  This is mainly intended as a convience for methods that want to take either a key or a key search criteria/

### JWK.allKeysAsync()

Returns a promise that resolve to an array of all matching keys from the keystore.  Arguments are as per [node-jose.get](https://github.com/cisco/node-jose#retrieving-keys).  If multiple keys match, then ALL keys is returned.

If the key is not found, the keystore will refresh (unless doNotReloadOnMissingKey was specified).  If the key is still not found, undefined will be returned.

### JWK.toJsonAsync(exportPrivate)
Returns a promise that resolves to the JSON representing the keystore.  If exportPrivate is true, then private keys are also exported, otherwise only public keys are exported.

### JWK.generateKeyAsync(kty, size, props, remember = true)
Generates a new key and saves it in the keystore.  The first three arguments match [node-jose.generate](https://github.com/cisco/node-jose#managing-keys).

The returned promise resolves to the new node-jose key.

### JWK.verifySignatureAsync(input)
Parses a JWS signed payload and returns the parsed data.  Throws an exception if the signature fails to verify.

If the key is not found, the keystore is refreshed (unless doNotReloadOnMissingKey was specified).

An exception is thrown on any validation failures.  Return values are as per [node-jose.JWS.createVerify](https://github.com/cisco/node-jose#verifying-a-jws).

The result will contain:
- header: The JSON header from the envelope
- payload: A Buffer object with the payload - to convert JSON responses to Javascript objects, first verify the header and then ```var result = JSON.parse(rv.payload.toString("utf8"));```
- signature: A Buffer object with the raw signature

### JWK.signAsync(key, content, options)
Signs the specified content with the node-jose key specified.

- key may be a node-jose key object or a query argument to node-jose.get to search the keystore for a key.
- options.encoding is the encoding to encode the content with (if it is a string).  Defaults to "utf8".
- options.format will be defaulted to "compact"
- See [node-jose.JWS.createSign](https://github.com/cisco/node-jose#signing-content) for more details on other options.

Returns a promise that resolves to the signed object.

### JWK.decryptAsync(input)
Decrypts a JWE encrypted payload and returns the enveloped data.

If the key is not found, the keystore is refreshed (unless doNotReloadOnMissingKey was specified).

Return values are as per [node-jose.JWS.createDecrypt](https://github.com/cisco/node-jose#decrypting-a-jwe).

The result will contain:
- key: The key used to decrypt the message
- header: The JSON header from the envelope
- plaintext: A Buffer object with the payload - to convert JSON responses to Javascript objects, first verify the header and then ```var result = JSON.parse(rv.payload.toString("utf8"));```

### JWK.encryptAsync(key, content, options)
Encrypts the specified content with the node-jose key specified.

- key may be a node-jose key object or a query argument to node-jose.get to search the keystore for a key.
- options.encoding is the encoding to encode the content with (if it is a string).  Defaults to "utf8".
- options.format will be defaulted to "compact"
- See [node-jose.JWS.createEncrypt](https://github.com/cisco/node-jose#encrypting-content) for more details on other options.

Returns a promise that resolves to the encrypted object.



# Contributing

Any PRs are welcome but please stick to following the general style of the code and stick to [CoffeeScript](http://coffeescript.org/).  I know the opinions on CoffeeScript are...highly varied...I will not go into this debate here - this project is currently written in CoffeeScript and I ask you maintain that for any PRs.