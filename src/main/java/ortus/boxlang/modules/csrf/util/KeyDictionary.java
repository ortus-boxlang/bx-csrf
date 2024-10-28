/**
 * [BoxLang]
 *
 * Copyright [2023] [Ortus Solutions, Corp]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ortus.boxlang.modules.csrf.util;

import ortus.boxlang.runtime.scopes.Key;

/**
 * The module's key dictionary.
 */
public class KeyDictionary {

	public static final Key	_MODULE_NAME		= Key.of( "csrf" );
	public static final Key	autoRotate			= Key.of( "autoRotate" );
	public static final Key	autoVerify			= Key.of( "autoVerify" );
	public static final Key	cacheStorage		= Key.of( "cacheStorage" );
	public static final Key	created				= Key.of( "created" );
	public static final Key	cgi					= Key.of( "cgi" );
	public static final Key	CSRFGenerateToken	= Key.of( "CSRFGenerateToken" );
	public static final Key	CSRFVerifyToken		= Key.of( "CSRFVerifyToken" );
	public static final Key	forceNew			= Key.of( "forceNew" );
	public static final Key	getHTTPRequestData	= Key.of( "getHTTPRequestData" );
	public static final Key	hash				= Key.of( "hash" );
	public static final Key	headerName			= Key.of( "headerName" );
	public static final Key	now					= Key.of( "now" );
	public static final Key	randRange			= Key.of( "randRange" );
	public static final Key	reapFrequency		= Key.of( "reapFrequency" );
	public static final Key	rotationInterval	= Key.of( "rotationInterval" );
	public static final Key	session				= Key.of( "session" );
	public static final Key	verifyMethods		= Key.of( "verifyMethods" );

}
