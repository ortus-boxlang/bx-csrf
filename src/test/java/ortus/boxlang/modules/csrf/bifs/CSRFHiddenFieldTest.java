package ortus.boxlang.modules.csrf.bifs;

import static com.google.common.truth.Truth.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ortus.boxlang.modules.csrf.BaseIntegrationTest;

public class CSRFHiddenFieldTest extends BaseIntegrationTest {

	@DisplayName( "It can test the hidden field" )
	@Test
	public void testExampleBIF() {
		runtime.executeSource(
		    """
		       application name="test" sessionmanagement="true";
		       result = CSRFHiddenField();
		    println( result )
		       """,
		    context );
		assertThat( variables.getAsString( result ) ).contains( "<input type='hidden' name='csrf' id='csrf' value=" );
	}

}
