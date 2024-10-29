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
package ortus.boxlang.modules.csrf.bifs;

import ortus.boxlang.modules.csrf.CSRFService;
import ortus.boxlang.modules.csrf.util.KeyDictionary;
import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.Argument;
import ortus.boxlang.web.context.WebRequestBoxContext;

@BoxBIF
public class CSRFHiddenField extends BIF {

	public CSRFHiddenField() {
		super();
		declaredArguments = new Argument[] {
		    new Argument( false, "string", Key.key, CSRFService.DEFAULT_TOKEN_KEY ),
		    new Argument( false, "boolean", KeyDictionary.forceNew, false )
		};
	}

	/**
	 * Generates a random token and stores it in the session cache to protect against Cross-Site Request Forgery (CSRF) attacks.
	 * <p>
	 * However, this method returns a hidden input field named "csrf"
	 *
	 * <pre>
	 * #CSRFHiddenField()#
	 * </pre>
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 *
	 * @argument.key The key to store the token under in the cache. Defaults to "default".
	 *
	 * @argument.forceNew If true, a new token will be generated and stored in the cache. Defaults to false.
	 *
	 * @return An input hidden field with your CSRF token
	 */
	public String _invoke( IBoxContext context, ArgumentsScope arguments ) {
		// Default key, or user-provided key
		String tokenKey = arguments.getAsString( Key.key ).trim();
		if ( tokenKey.isEmpty() ) {
			tokenKey = CSRFService.DEFAULT_TOKEN_KEY;
		}
		Boolean	forceNew		= arguments.getAsBoolean( KeyDictionary.forceNew );

		// Generate the token
		String	generatedToken	= CSRFService.generate( context.getParentOfType( WebRequestBoxContext.class ), tokenKey, forceNew );

		// Build the hidden field: "<input type='hidden' name='csrf' id='csrf' value='#csrfToken( argumentCollection=arguments )#'>"
		return String.format(
		    "<input type='hidden' name='csrf' id='csrf' value='%s'>",
		    generatedToken
		);

	}

}
