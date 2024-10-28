package ortus.boxlang.modules.csrf.bifs;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ortus.boxlang.modules.csrf.BaseIntegrationTest;
import ortus.boxlang.modules.csrf.util.KeyDictionary;
import ortus.boxlang.runtime.types.IStruct;

public class CSRFGenerateTokenTest extends BaseIntegrationTest {

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
		IStruct moduleSettings = runtime.getModuleService().getModuleSettings( moduleName );
		moduleSettings.put( KeyDictionary.cacheStorage, "default" );
		runtime.executeSource(
		    """
		    application name="test" sessionmanagement="true";
		    result = CSRFGenerateToken();
		    """,
		    context );
		assertEquals( 40, variables.getAsString( result ).length() );
	}

}
