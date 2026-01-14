# ⚡︎ BoxLang Module: BoxLang CSRF

The CSRF module provides the functionality to generate and verify [Cross-Site Request Forgery](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) tokens to Boxlang Web Runtimes.

## Built-In Functions

This module contributes the following native functions to the boxlang runtime:

* `CSRFGenerateToken( [string key='default'], [boolean forceNew=false] )` - this function generates the CSRF token.  The optional `key` argument can be provided to create and scope a specific token.
* `CSRFVerifyToken( required string token, [ string key ] )` - this function verifies the token created by the above method.  The `key` argument must be passed if the token was generated with the that argument.
* `CSRFRotate()` - this function will rotate all tokens in the cache by removing them.  This will force the next request to generate a new token.
* `CSRFHiddenField( [string key='default'], [boolean forceNew=false] )` - Generates a hidden field with a csrf in it as the value.  The name of the field is `csrf`

## Configuration

The module may be configured using the following settings in your `boxlang.json` file.  The settings noted below are the defaults:

```javascript
"modules": {
	"csrf": {
		"settings": {
			// The cache storage to use can be either a cache ( e.g. `default` ) name or the default "session" to store the keys within the user sessions cache
			"cacheStorage" : "session",
			// The duration in minutes to perform a cache reap of expired tokens
			"reapFrequency" : 1,
			// The interval in minutes to rotate the token if autoRotate is enabled
			"rotationInterval" : 30,
			// The interval in seconds within which, if a token's expiration is impending, we force generate new token for the user.
			"timeoutSkew" : 60,
			// Whether the the presence of the token should be verified automatically for the verifyMethods
			"autoVerify" : false,
			// The name of the header to check for automatic token verification, if applicable
			"headerName" : "x-csrf-token",
			// The methods to verify the token presence, if enabled
			"verifyMethods" : [ "POST", "PUT", "PATCH", "DELETE" ],
		}
	}
}
```

## Token Storage

Tokens may be stored any named [caches configured](https://boxlang.ortusbooks.com/getting-started/configuration#caches) within the Boxlang runtime.  By default the user `session` cache is used for storage.

## Token Expiration

By default, the module is configured to rotate all user csrf tokens every 30 minutes.  This setting may be changed to another duration of minutes using the `rotationInterval` module setting.  If you do NOT want the tokens to EVER expire, then use the value of 0 zero. Note that using in-memory caches will result in token expiration on runtime shutdown.

## Auto-Verification

The module may be enabled to perform auto-verification of CSRF inbound headers.  If enabled, a check will be performed at the beginning of the request for the presence of the configured CSRF `headerName` setting and, if verification fails, an error will be thrown.  Note that any tokens created for use in auto-verification must omit the `key` argument, as only the default token may be verified.

## Cache Reaping

A scheduler is enabled with the module which will perform a check and remove all expired tokens from the cache at a frequency of minutes ( default `1` ).  If you wish to adjust this, you make change the `reapFrequency` setting to your desired interval.

```
|:------------------------------------------------------:|
| ⚡︎ B o x L a n g ⚡︎
| Dynamic : Modular : Productive
|:------------------------------------------------------:|
```

<blockquote>
	Copyright Since 2023 by Ortus Solutions, Corp
	<br>
	<a href="https://www.boxlang.io">www.boxlang.io</a> |
	<a href="https://www.ortussolutions.com">www.ortussolutions.com</a>
</blockquote>

<p>&nbsp;</p>

## Ortus Sponsors

BoxLang is a professional open-source project and it is completely funded by the [community](https://patreon.com/ortussolutions) and [Ortus Solutions, Corp](https://www.ortussolutions.com).  Ortus Patreons get many benefits like a cfcasts account, a FORGEBOX Pro account and so much more.  If you are interested in becoming a sponsor, please visit our patronage page: [https://patreon.com/ortussolutions](https://patreon.com/ortussolutions)

### THE DAILY BREAD

 > "I am the way, and the truth, and the life; no one comes to the Father, but by me (JESUS)" Jn 14:1-12
