package ortus.boxlang.modules.csrf.bifs;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ortus.boxlang.modules.csrf.BaseIntegrationTest;
import ortus.boxlang.modules.csrf.util.KeyDictionary;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.IStruct;

public class CSRFGenerateTokenTest extends BaseIntegrationTest {

	@DisplayName( "It can test the BIF CSRFGenerateToken" )
	@Test
	public void testExampleBIF() {
		runtime.executeSource(
		    """
		    bx:application name="test" sessionmanagement="true";
		    result = CSRFGenerateToken();
		    """,
		    context );
		assertEquals( 40, variables.getAsString( result ).length() );
	}

	@DisplayName( "It can test the BIF CSRFGenerateToken with a custom token key" )
	@Test
	public void testBIFCustomTokenKey() {
		runtime.executeSource(
		    """
		    bx:application name="test" sessionmanagement="true";
		    result = CSRFGenerateToken( "myUnitTest" );
		    """,
		    context );
		assertEquals( 40, variables.getAsString( result ).length() );
	}

	@DisplayName( "It can test the BIF CSRFGenerateToken with a force new token" )
	@Test
	public void testBIFForceNewToken() {
		// @formatter:off
		runtime.executeSource(
		    """
		       bx:application name="test" sessionmanagement="true";
				CSRFRotate();
				original = CSRFGenerateToken( "myUnitTest" );
				forced = CSRFGenerateToken( "myUnitTest", true );
				println( original )
				println( forced )
		       """,
		    context );
		// @formatter:on
		String	original	= variables.getAsString( Key.of( "original" ) );
		String	forced		= variables.getAsString( result );
		assertThat( original ).isNotEqualTo( forced );
	}

	@DisplayName( "It can test the BIF CSRFGenerateToken using an alternate cache storage" )
	@Test
	public void testBIFCacheSwitch() {
		IStruct moduleSettings = runtime.getModuleService().getModuleSettings( moduleName );
		moduleSettings.put( KeyDictionary.cacheStorage, "default" );
		runtime.executeSource(
		    """
		    bx:application name="test" sessionmanagement="true";
		    result = CSRFGenerateToken();
		    """,
		    context );
		assertEquals( 40, variables.getAsString( result ).length() );
	}

}
