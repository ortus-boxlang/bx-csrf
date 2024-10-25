package ortus.boxlang.modules.csrf.bifs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.HashMap;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import ortus.boxlang.modules.csrf.ModuleKeys;
import ortus.boxlang.runtime.BoxRuntime;
import ortus.boxlang.runtime.application.BaseApplicationListener;
import ortus.boxlang.runtime.scopes.IScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.scopes.VariablesScope;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;
import ortus.boxlang.web.context.WebRequestBoxContext;
import ortus.boxlang.web.exchange.BoxCookie;
import ortus.boxlang.web.exchange.IBoxHTTPExchange;

public class CSRFGenerateTokenTest {

	static BoxRuntime			runtime;
	public final String			TEST_WEBROOT	= Path.of( "src/test/resources/webroot" ).toAbsolutePath().toString();
	public WebRequestBoxContext	context;
	public IScope				variables;
	public IBoxHTTPExchange		mockExchange;
	public String				requestURI		= "/";
	public Key					result			= Key.of( "result" );

	@BeforeAll
	public static void setUp() {
		runtime = BoxRuntime.getInstance( true, Path.of( "src/test/resources/boxlang.json" ).toString() );
	}

	@BeforeEach
	public void setupEach() {
		// Mock a connection
		mockExchange = Mockito.mock( IBoxHTTPExchange.class );
		// Mock some objects which are used in the context
		when( mockExchange.getRequestCookies() ).thenReturn( new BoxCookie[ 0 ] );
		when( mockExchange.getRequestHeaderMap() ).thenReturn( new HashMap<String, String[]>() );
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

	@DisplayName( "It can test the BIF CSRFGenerateToken" )
	@Test
	public void testExampleBIF() {
		runtime.executeSource(
		    """
		    application name="test" sessionmanagement="true";
		    result = CSRFGenerateToken();
		    """,
		    context );
		assertEquals( 40, variables.getAsString( result ).length() );
	}

	@DisplayName( "It can test the BIF CSRFGenerateToken using an alternate cache storage" )
	@Test
	public void testBIFCacheSwitch() {
		IStruct moduleSettings = runtime.getModuleService().getModuleSettings( Key.of( "csrf" ) );
		moduleSettings.put( ModuleKeys.cacheStorage, "default" );
		runtime.executeSource(
		    """
		    application name="test" sessionmanagement="true";
		    result = CSRFGenerateToken();
		    """,
		    context );
		assertEquals( 40, variables.getAsString( result ).length() );
	}

}
