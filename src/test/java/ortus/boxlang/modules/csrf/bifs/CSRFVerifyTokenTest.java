package ortus.boxlang.modules.csrf.bifs;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ortus.boxlang.modules.csrf.BaseIntegrationTest;

public class CSRFVerifyTokenTest extends BaseIntegrationTest {

	@DisplayName( "It can test the BIF CSRFVerifyToken" )
	@Test
	public void testBIF() {
		// @formatter:off
		runtime.executeSource(
		    """
				application name="test" sessionmanagement="true";
				token = CSRFGenerateToken();
				result = CSRFVerifyToken(token);
		    """,
		    context );
		assertEquals( true, variables.getAsBoolean( result ) );

		// test with key name
		runtime.executeSource(
		    """
		       application name="test" sessionmanagement="true";
		       token = CSRFGenerateToken( "test" );
		    result = CSRFVerifyToken(token, "test" );
		       """,
		    context );
		assertEquals( true, variables.getAsBoolean( result ) );

		// test with key name
		runtime.executeSource(
		    """
		    result = CSRFVerifyToken( "blah" );
		       """,
		    context );
		assertEquals( false, variables.getAsBoolean( result ) );
		// @formatter:on
	}

}
