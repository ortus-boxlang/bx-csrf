package ortus.boxlang.modules.csrf;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ortus.boxlang.runtime.scopes.Key;

public class CSRFServiceTest extends BaseIntegrationTest {

	@DisplayName( "It should generate a new token when existing token expiration falls within timeoutSkew" )
	@Test
	public void testTimeoutSkewGeneratesNewToken() {
		runtime.executeSource(
		    """
		    bx:application name="test" sessionmanagement="true";

		    // Generate first token to establish the session and cache structure
		    tokenKey = "testTimeoutSkew";
		    token1 = CSRFGenerateToken( tokenKey );

		    // Now directly manipulate the cache entry to have an expiration within timeoutSkew (60 seconds)
		    // Get the session context and cache provider from the runtime
		    requestContext = getBoxContext();
		    sessionContext = requestContext.getParentOfType( createObject( "java", "ortus.boxlang.runtime.context.SessionBoxContext" ) );
		    appContext = requestContext.getParentOfType( createObject( "java", "ortus.boxlang.runtime.context.ApplicationBoxContext" ) );
		    cacheProvider = appContext.getApplication().getSessionsCache();

		    // Build the cache key manually
		    session = sessionContext.getSession();
		    cacheKey = "bl_csrf_tokens_" & session.getCacheKey() & "_" & tokenKey;

		    // Get current time and set token to expire in 30 seconds (within 60 second timeoutSkew)
		    now = now();
		    expiration = dateAdd( "s", 30, now );

		    // Create new cache entry with expiration within timeoutSkew
		    tokenStruct = {
		        "token": token1,
		        "created": dateTimeFormat( now, "iso8601" ),
		        "expires": dateTimeFormat( expiration, "iso8601" )
		    };

		    // Set the cache entry with the modified expiration
		    cacheProvider.set( cacheKey, tokenStruct );

		    // Now generate a token - should create a new one because existing expires within timeoutSkew
		    token2 = CSRFGenerateToken( tokenKey, false );

		    result = {
		        "token1": token1,
		        "token2": token2,
		        "areTokensDifferent": ( token1 != token2 ),
		        "token1Length": len( token1 ),
		        "token2Length": len( token2 )
		    };
		    """,
		    context );

		// Verify the results
		var		result				= variables.getAsStruct( Key.of( "result" ) );
		String	token1				= result.getAsString( Key.of( "token1" ) );
		String	token2				= result.getAsString( Key.of( "token2" ) );
		Boolean	areTokensDifferent	= result.getAsBoolean( Key.of( "areTokensDifferent" ) );
		Integer	token1Length		= result.getAsInteger( Key.of( "token1Length" ) );
		Integer	token2Length		= result.getAsInteger( Key.of( "token2Length" ) );

		// Verify that a new token was generated due to timeoutSkew
		assertThat( areTokensDifferent ).isTrue();
		assertThat( token1Length ).isEqualTo( 40 );
		assertThat( token2Length ).isEqualTo( 40 );
		assertNotEquals( token1, token2 );
	}

	@DisplayName( "It should NOT generate a new token when existing token expiration is beyond timeoutSkew" )
	@Test
	public void testTokenNotRegeneratedWhenExpirationBeyondTimeoutSkew() {
		runtime.executeSource(
		    """
		    bx:application name="test" sessionmanagement="true";

		    // Generate first token to establish the session and cache structure
		    tokenKey = "testBeyondTimeoutSkew";
		    token1 = CSRFGenerateToken( tokenKey );

		    // Now directly manipulate the cache entry to have an expiration beyond timeoutSkew (60 seconds)
		    // Get the session context and cache provider from the runtime
		    requestContext = getBoxContext();
		    sessionContext = requestContext.getParentOfType( createObject( "java", "ortus.boxlang.runtime.context.SessionBoxContext" ) );
		    appContext = requestContext.getParentOfType( createObject( "java", "ortus.boxlang.runtime.context.ApplicationBoxContext" ) );
		    cacheProvider = appContext.getApplication().getSessionsCache();

		    // Build the cache key manually
		    session = sessionContext.getSession();
		    cacheKey = "bl_csrf_tokens_" & session.getCacheKey() & "_" & tokenKey;

		    // Get current time and set token to expire in 120 seconds (beyond 60 second timeoutSkew)
		    now = now();
		    expiration = dateAdd( "s", 240, now );

		    // Create new cache entry with expiration beyond timeoutSkew
		    tokenStruct = {
		        "token": token1,
		        "created": dateTimeFormat( now, "iso8601" ),
		        "expires": dateTimeFormat( expiration, "iso8601" )
		    };

		    // Set the cache entry with the modified expiration
		    cacheProvider.set( cacheKey, tokenStruct );

		    // Now generate a token - should return the same one because it doesn't expire within timeoutSkew
		    token2 = CSRFGenerateToken( tokenKey, false );

		    result = {
		        "token1": token1,
		        "token2": token2,
		        "areTokensSame": ( token1 == token2 ),
		        "tokenLength": len( token1 )
		    };
		    """,
		    context );

		// Verify the results
		var		result			= variables.getAsStruct( Key.of( "result" ) );
		String	token1			= result.getAsString( Key.of( "token1" ) );
		String	token2			= result.getAsString( Key.of( "token2" ) );
		Boolean	areTokensSame	= result.getAsBoolean( Key.of( "areTokensSame" ) );
		Integer	tokenLength		= result.getAsInteger( Key.of( "tokenLength" ) );

		// Verify that the same token was returned (not regenerated)
		assertThat( areTokensSame ).isTrue();
		assertThat( tokenLength ).isEqualTo( 40 );
		assertThat( token1 ).isEqualTo( token2 );
	}

	@DisplayName( "It should generate a new token when forceNew is true regardless of timeoutSkew" )
	@Test
	public void testForceNewIgnoresTimeoutSkew() {
		runtime.executeSource(
		    """
		    bx:application name="test" sessionmanagement="true";

		    // Generate first token
		    tokenKey = "testForceNew";
		    token1 = CSRFGenerateToken( tokenKey );

		    // Immediately try to generate with forceNew=true
		    token2 = CSRFGenerateToken( tokenKey, true );

		    result = {
		        "token1": token1,
		        "token2": token2,
		        "areTokensDifferent": ( token1 != token2 ),
		        "token1Length": len( token1 ),
		        "token2Length": len( token2 )
		    };
		    """,
		    context );

		// Verify the results
		var		result				= variables.getAsStruct( Key.of( "result" ) );
		String	token1				= result.getAsString( Key.of( "token1" ) );
		String	token2				= result.getAsString( Key.of( "token2" ) );
		Boolean	areTokensDifferent	= result.getAsBoolean( Key.of( "areTokensDifferent" ) );
		Integer	token1Length		= result.getAsInteger( Key.of( "token1Length" ) );
		Integer	token2Length		= result.getAsInteger( Key.of( "token2Length" ) );

		// Verify that a new token was generated even though we forced it
		assertThat( areTokensDifferent ).isTrue();
		assertThat( token1Length ).isEqualTo( 40 );
		assertThat( token2Length ).isEqualTo( 40 );
		assertNotEquals( token1, token2 );
	}

}
