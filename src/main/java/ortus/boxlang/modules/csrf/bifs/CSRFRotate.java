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
import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.web.context.WebRequestBoxContext;

@BoxBIF
public class CSRFRotate extends BIF {

	public CSRFRotate() {
		super();
	}

	/**
	 * Rotates the CSRF token(s) in the session cache to protect against Cross-Site Request Forgery (CSRF) attacks.
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 */
	@Override
	public Object _invoke( IBoxContext context, ArgumentsScope arguments ) {
		return CSRFService.rotate( context.getParentOfType( WebRequestBoxContext.class ) );
	}

}
