package ortus.boxlang.modules.csrf;

import ortus.boxlang.modules.csrf.util.KeyDictionary;
import ortus.boxlang.runtime.BoxRuntime;
import ortus.boxlang.runtime.application.Session;
import ortus.boxlang.runtime.cache.filters.WildcardFilter;
import ortus.boxlang.runtime.cache.providers.ICacheProvider;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.context.SessionBoxContext;
import ortus.boxlang.runtime.dynamic.casters.LongCaster;
import ortus.boxlang.runtime.dynamic.casters.StringCaster;
import ortus.boxlang.runtime.dynamic.casters.StructCaster;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.services.CacheService;
import ortus.boxlang.runtime.services.FunctionService;
import ortus.boxlang.runtime.services.ModuleService;
import ortus.boxlang.runtime.types.DateTime;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.Struct;
import ortus.boxlang.runtime.types.exceptions.BoxRuntimeException;
import ortus.boxlang.runtime.types.util.BLCollector;
import ortus.boxlang.web.context.WebRequestBoxContext;
import ortus.boxlang.web.exchange.IBoxHTTPExchange;

public class CSRFService {

	// Public constants
	public static final String		CACHE_PREFIX		= "bl_csrf_tokens_";
	public static final String		DEFAULT_TOKEN_KEY	= "default";

	// Private constants
	private static final String		RANGE_ALGORITHM		= "SHA1PRNG";
	private static final String		HASH_ALGORITHM		= "SHA-256";
	private static final Key		X_CLUSTER_CLIENT_IP	= Key.of( "x-cluster-client-ip" );
	private static final Key		X_FORWARDED_FOR		= Key.of( "X-Forwarded-For" );

	// Private vars
	private static BoxRuntime		runtime;
	private static FunctionService	functionService;
	private static CacheService		cacheService;
	private static ModuleService	moduleService;
	private static IStruct			moduleSettings;
	private static Key				cacheStorage;
	private static Long				rotationInterval;

	static {
		runtime				= BoxRuntime.getInstance();
		functionService		= runtime.getFunctionService();
		cacheService		= runtime.getCacheService();
		moduleService		= runtime.getModuleService();
		moduleSettings		= moduleService.getModuleSettings( KeyDictionary._MODULE_NAME );
		cacheStorage		= Key.of( moduleSettings.getAsString( KeyDictionary.cacheStorage ) );
		rotationInterval	= LongCaster.cast( moduleSettings.get( KeyDictionary.rotationInterval ) );
	}

	/**
	 * Generates a random token and stores it in the session cache to protect against Cross-Site Request Forgery (CSRF) attacks.
	 *
	 * @param context  The web context used.
	 * @param tokenKey The token key to store the token under in the cache. Defaults to "default".
	 * @param forceNew If true, a new token will be generated and stored in the cache. Defaults to false.
	 *
	 * @return The generated token.
	 */
	public static String generate( WebRequestBoxContext context, String tokenKey, Boolean forceNew ) {
		// Get the user's session info
		SessionBoxContext	sessionContext	= validateSessionContext( context );
		Session				session			= sessionContext.getSession();
		Key					sessionId		= session.getID();

		// Get the cache provider to use for storing CSRF tokens
		ICacheProvider		cacheProvider	= getCacheProvider();
		String				cacheKey		= CACHE_PREFIX + session.getCacheKey();
		Key					assignment		= Key.of( tokenKey );

		// IMPORTANT: Get now according to timezone info of application
		DateTime			now				= ( DateTime ) functionService
		    .getGlobalFunction( KeyDictionary.now )
		    .invoke( context, false );

		// Get the token storage from the cache with the active tokens only
		IStruct				activeTokens	= StructCaster.cast( cacheProvider.getOrSet( cacheKey, Struct::new ) )
		    .entrySet()
		    .stream()
			// @formatter:off
		    .filter( entry -> {
				DateTime expires = new DateTime( StructCaster.cast( entry.getValue() ).getAsString( Key.expires ) );
				return expires.getWrapped().isAfter( now.getWrapped() );
			} )
			// @formatter:on
		    .collect( BLCollector.toStruct() );

		// If the token doesn't exist or we're forcing a new one, generate a new token
		if ( forceNew || !activeTokens.containsKey( assignment ) ) {
			activeTokens.put( assignment, Struct.of(
			    Key.token, generateNewToken( context, sessionId.toString(), tokenKey ),
			    KeyDictionary.created, now.toISOString(),
			    Key.expires, now.modify( "n", rotationInterval ).toISOString()
			) );
			cacheProvider.set( cacheKey, activeTokens );
		}

		return activeTokens.getAsStruct( assignment ).getAsString( Key.token );
	}

	/**
	 * Verify that the token provided matches the token stored in the cache.
	 *
	 * @param context The web context used.
	 * @param token   The token to verify.
	 * @param key     The key against which to verify the token.
	 *
	 * @return True if the token is valid, false otherwise.
	 */
	public static boolean verify( WebRequestBoxContext context, String token, String key ) {
		// Get the user's session info
		SessionBoxContext	sessionContext	= validateSessionContext( context );
		Session				session			= sessionContext.getSession();

		// Which key to store the token under in the cache
		Key					assignment		= Key.of( key.isEmpty() ? DEFAULT_TOKEN_KEY : key );

		// Get the cache provider to use for storing CSRF tokens + tokens
		ICacheProvider		cacheProvider	= getCacheProvider();
		String				cacheKey		= CACHE_PREFIX + session.getCacheKey();
		IStruct				activeTokens	= StructCaster.cast( cacheProvider.getOrSet( cacheKey, Struct::new ) );

		// Token key doesn't exist in the cache
		if ( !activeTokens.containsKey( assignment ) ) {
			return false;
		}

		// Token assignment key exists, check if the token matches and if it has not expired
		IStruct tokenData = activeTokens.getAsStruct( assignment );
		if ( tokenData.getAsString( Key.token ).equals( token ) ) {
			DateTime	expires	= new DateTime( tokenData.getAsString( Key.expires ) );
			DateTime	now		= ( DateTime ) functionService.getGlobalFunction( KeyDictionary.now ).invoke( context, false );
			return expires.getWrapped().isAfter( now.getWrapped() );
		}

		return false;
	}

	/**
	 * Wipes the entire token storage for a user's session.
	 *
	 * @param context The web context used.
	 *
	 * @return True if the token storage was successfully wiped, false otherwise.
	 */
	public static boolean rotate( WebRequestBoxContext context ) {
		SessionBoxContext	sessionContext	= validateSessionContext( context );
		Session				session			= sessionContext.getSession();

		return getCacheProvider().clear( CACHE_PREFIX + session.getCacheKey() );
	}

	/**
	 * Reaps expired tokens from the cache.
	 * It will find all the activeTokens storage per session and remove any expired tokens
	 * from those storages.
	 * <p>
	 * This reap usually runs from a scheduler.
	 */
	public static void reap() {
		IBoxContext	reapContext	= runtime.getRuntimeContext();
		DateTime	now			= ( DateTime ) functionService
		    .getGlobalFunction( KeyDictionary.now )
		    .invoke( reapContext, false );

		getCacheProvider()
		    .get( new WildcardFilter( CACHE_PREFIX ) )
		    .entrySet()
		    .stream()
		    .forEach( entry -> {
			    Key	storageKey		= entry.getKey();
			    IStruct activeTokens = StructCaster.cast( entry.getValue() );

			    getCacheProvider()
			        .set(
			            storageKey.getName(),
			            activeTokens.entrySet().stream().filter( item -> {
				            DateTime expires = new DateTime( StructCaster.cast( item.getValue() ).getAsString( Key.expires ) );
				            return expires.getWrapped().isAfter( now.getWrapped() );
			            } ).collect( BLCollector.toStruct() )
			        );
		    } );
	}

	/**
	 * --------------------------------------------------------------------------
	 * Private Helpers
	 * --------------------------------------------------------------------------
	 */

	/**
	 * The cache provider to use for storing CSRF tokens.
	 *
	 * @return The cache provider to use for storing CSRF tokens.
	 */
	private static ICacheProvider getCacheProvider() {
		return cacheService.getCache( cacheStorage );
	}

	/**
	 * Verify that the current context is a session context.
	 *
	 * @param context The context to validate.
	 *
	 * @throws BoxRuntimeException If the context is not a session context.
	 */
	private static SessionBoxContext validateSessionContext( WebRequestBoxContext context ) {
		SessionBoxContext sessionContext = context.getParentOfType( SessionBoxContext.class );
		if ( sessionContext == null ) {
			throw new BoxRuntimeException( "CSRF Tokens may not be generated or verified unless session management is enabled" );
		}
		return sessionContext;
	}

	/**
	 * Generate a new CSRF token according to the passed parameters.
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param sessionId The ID of the user's session.
	 * @param key       The key to store the token under in the cache.
	 *
	 * @return The generated token.
	 */
	private static String generateNewToken( WebRequestBoxContext context, String sessionId, String key ) {
		IStruct	arguments	= Struct.of(
		    Key.number1, 0,
		    Key.number2, 65535,
		    Key.algorithm, RANGE_ALGORITHM
		);
		Long	range		= LongCaster
		    .cast(
		        functionService.getGlobalFunction( KeyDictionary.randRange ).invoke( context, arguments, false, KeyDictionary.randRange )
		    );

		// Ensure tokenBase is sufficiently random for this user and could never be guessed
		String	tokenBase	= String.format(
		    "%s%s%s%s%s",
		    key,
		    getRealIP( context ),
		    range,
		    System.currentTimeMillis(),
		    sessionId
		);
		String	hashedToken	= StringCaster.cast(
		    functionService
		        .getGlobalFunction( KeyDictionary.hash )
		        .invoke(
		            context,
		            Struct.of(
		                Key.input, tokenBase,
		                Key.algorithm, HASH_ALGORITHM
		            ),
		            false,
		            KeyDictionary.hash
		        )
		);

		// Return a 40 character hash as the new token
		return hashedToken.substring( 0, 40 ).toUpperCase();
	}

	/**
	 * Get the real IP address of the client making the request.
	 *
	 * @param context The context in which the BIF is being invoked.
	 *
	 * @return The real IP address of the client making the request.
	 */
	private static String getRealIP( WebRequestBoxContext context ) {
		IBoxHTTPExchange	exchange	= context.getHTTPExchange();
		IStruct				headers		= new Struct();

		exchange.getRequestHeaderMap().forEach( ( key, values ) -> headers.put( key, values[ 0 ] ) );

		if ( headers.containsKey( X_CLUSTER_CLIENT_IP ) ) {
			return headers.getAsString( X_CLUSTER_CLIENT_IP );
		} else if ( headers.containsKey( X_FORWARDED_FOR ) ) {
			return headers.getAsString( X_FORWARDED_FOR );
		}

		// Default it
		String remoteIP = ( String ) context.getScope( KeyDictionary.cgi ).getOrDefault( Key.remote_addr, "" );
		return remoteIP.isEmpty() ? "127.0.0.1" : remoteIP;
	}

}
