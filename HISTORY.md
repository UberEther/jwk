0.4.0: Published 10/29/2015
- Update auto-refresh-from-url, bluebird, node-jose, and istanpul
- Rename refreshIfNeeded API to loadAsync to follow new auto-refresh-from-url convention
- Renamed jwk option to jwks
- Added loader and file options
- Added JWK.Loader to expose auto-refresh-from-url
- Rename JWK class to JWKS to be more accurate
- Split crypto op tests away from core JWKS testing to make tests easier to read

0.3.0: Published 10/8/2015
- Added jwk constructor option

0.2.0: Published 10/7/2015
- Added option to pass key query arguments to sign and encrypt methods
- Increase mocha timeout to 10 seconds - some operations were randomly timing out on Travis
- Bump node-jose version to fix EC encryption issue

0.1.0: Published 10/6/2015
- Initial release