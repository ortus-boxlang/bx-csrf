/**
 * [BoxLang]
 *
 * Copyright [2023] [Ortus Solutions, Corp]
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
 * License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS"
 * BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package ortus.boxlang.modules.csrf.interceptors;

import ortus.boxlang.modules.csrf.util.KeyDictionary;
import ortus.boxlang.runtime.BoxRuntime;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.dynamic.casters.BooleanCaster;
import ortus.boxlang.runtime.dynamic.casters.StringCaster;
import ortus.boxlang.runtime.dynamic.casters.StructCaster;
import ortus.boxlang.runtime.events.BaseInterceptor;
import ortus.boxlang.runtime.events.InterceptionPoint;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.Array;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.Struct;
import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;
import ortus.boxlang.runtime.types.util.BLCollector;
import ortus.boxlang.web.context.WebRequestBoxContext;

/**
 * Listens to when sessions get created to manipulate them for CFML compatibility
 */
public class CSRFVerifier extends BaseInterceptor {

	BoxRuntime	runtime			= BoxRuntime.getInstance( true );
	IStruct		moduleSettings	= runtime.getModuleService().getModuleSettings( KeyDictionary._MODULE_NAME );
	Boolean		enabled			= BooleanCaster.cast( moduleSettings.getAsBoolean( KeyDictionary.autoVerify ) );

	/**
	 * On Request Interception Contribution
	 *
	 * @param interceptData The struct containing the context and arguments of the BIF Invocation
	 */
	@InterceptionPoint
	public void onRequest( IStruct interceptData ) {

		if ( !enabled ) {
			return;
		}

		IBoxContext context = ( IBoxContext ) interceptData.get( Key.context );

		if ( ! ( context instanceof WebRequestBoxContext ) ) {
			return;
		}

		WebRequestBoxContext	webContext		= ( WebRequestBoxContext ) context;

		IStruct					requestData		= StructCaster.cast( runtime.getFunctionService()
		    .getGlobalFunction( KeyDictionary.getHTTPRequestData )
		    .invoke(
		        context,
		        Struct.of(),
		        false,
		        KeyDictionary.getHTTPRequestData
		    ) );
		Key						checkHeader		= Key.of( moduleSettings.getAsString( KeyDictionary.headerName ) );
		Array					checkMethods	= moduleSettings.getAsArray( KeyDictionary.verifyMethods )
		    .stream()
		    .map( StringCaster::cast )
		    .map( String::toUpperCase )
		    .collect( BLCollector.toArray() );
		IStruct					requestHeaders	= requestData.getAsStruct( Key.headers );

		if ( checkMethods.contains( requestData.getAsString( Key.method ).toUpperCase() ) && requestHeaders.containsKey( checkHeader ) ) {
			boolean verified = BooleanCaster.cast( runtime.getFunctionService()
			    .getGlobalFunction( KeyDictionary.CSRFVerifyToken )
			    .invoke(
			        webContext,
			        Struct.of(
			            Key.token, requestHeaders.getAsString( checkHeader )
			        ),
			        false,
			        KeyDictionary.CSRFVerifyToken
			    ) );
			if ( !verified ) {
				throw new BoxRuntimeException( "The inbound CSRF Token in the header [" + checkHeader.getName() + "] is not valid" );
			}
		}

	}

}
