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
package ortus.boxlang.modules.csrf;

import static org.mockito.Mockito.when;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mockito;

import ortus.boxlang.modules.csrf.util.KeyDictionary;
import ortus.boxlang.runtime.BoxRuntime;
import ortus.boxlang.runtime.application.BaseApplicationListener;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.modules.ModuleRecord;
import ortus.boxlang.runtime.scopes.IScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.scopes.VariablesScope;
import ortus.boxlang.runtime.services.ModuleService;
import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;
import ortus.boxlang.web.context.WebRequestBoxContext;
import ortus.boxlang.web.exchange.BoxCookie;
import ortus.boxlang.web.exchange.IBoxHTTPExchange;

/**
 * Use this as a base integration test for your non web-support package
 * modules. If you want web based testing, use the BaseWebIntegrationTest
 */
public abstract class BaseIntegrationTest {

	protected static BoxRuntime		runtime;
	protected static ModuleService	moduleService;
	protected static ModuleRecord	moduleRecord;
	protected static Key			result			= new Key( "result" );
	protected static Key			moduleName		= KeyDictionary._MODULE_NAME;
	protected static final String	TEST_WEBROOT	= Path.of( "src/test/resources/webroot" ).toAbsolutePath().toString();
	protected static final String	requestURI		= "/";
	protected WebRequestBoxContext	context;
	protected IScope				variables;
	protected IBoxHTTPExchange		mockExchange;

	@BeforeAll
	public static void setup() {
		runtime			= BoxRuntime.getInstance( true, Path.of( "src/test/resources/boxlang.json" ).toString() );
		moduleService	= runtime.getModuleService();
		// Load the module
		loadModule( runtime.getRuntimeContext() );
	}

	@BeforeEach
	public void setupEach() {
		// Mock a connection
		mockExchange = Mockito.mock( IBoxHTTPExchange.class );
		// Mock some objects which are used in the context
		when( mockExchange.getRequestCookies() ).thenReturn( new BoxCookie[ 0 ] );
		when( mockExchange.getRequestHeaderMap() ).thenReturn( new HashMap<String, String[]>() );
		when( mockExchange.getRequestMethod() ).thenReturn( "GET" );
		when( mockExchange.getResponseWriter() ).thenReturn( new PrintWriter( OutputStream.nullOutputStream() ) );

		// Create the mock contexts
		context		= new WebRequestBoxContext( runtime.getRuntimeContext(), mockExchange, TEST_WEBROOT );
		variables	= context.getScopeNearby( VariablesScope.name );

		try {
			context.loadApplicationDescriptor( new URI( requestURI ) );
		} catch ( URISyntaxException e ) {
			throw new BoxRuntimeException( "Invalid URI", e );
		}

		BaseApplicationListener appListener = context.getApplicationListener();
		appListener.onRequestStart( context, new Object[] { requestURI } );
	}

	protected static void loadModule( IBoxContext context ) {
		if ( !runtime.getModuleService().hasModule( moduleName ) ) {
			System.out.println( "Loading module: " + moduleName );
			String physicalPath = Paths.get( "./build/module" ).toAbsolutePath().toString();
			moduleRecord = new ModuleRecord( physicalPath );

			moduleService.getRegistry().put( moduleName, moduleRecord );

			moduleRecord
			    .loadDescriptor( context )
			    .register( context )
			    .activate( context );
		} else {
			System.out.println( "Module already loaded: " + moduleName );
		}
	}

}
