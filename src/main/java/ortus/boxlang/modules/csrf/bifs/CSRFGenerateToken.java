package ortus.boxlang.modules.csrf.bifs;

import ortus.boxlang.modules.csrf.ModuleKeys;
import ortus.boxlang.runtime.application.Session;
import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.cache.providers.ICacheProvider;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.context.RequestBoxContext;
import ortus.boxlang.runtime.context.SessionBoxContext;
import ortus.boxlang.runtime.dynamic.casters.LongCaster;
import ortus.boxlang.runtime.dynamic.casters.StringCaster;
import ortus.boxlang.runtime.dynamic.casters.StructCaster;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.IScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.Argument;
import ortus.boxlang.runtime.types.DateTime;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.Struct;
import ortus.boxlang.runtime.types.util.BLCollector;
import ortus.boxlang.web.context.WebRequestBoxContext;
import ortus.boxlang.web.exchange.IBoxHTTPExchange;

@BoxBIF
public class CSRFGenerateToken extends BIF {

	private static final String	rangeAlgorithm		= "SHA1PRNG";
	private static final String	hashAlgorithm		= "SHA-256";
	private static final Key	clusterClientIPKey	= Key.of( "x-cluster-client-ip" );
	private static final Key	forwardedForKey		= Key.of( "X-Forwarded-For" );

	public CSRFGenerateToken() {
		super();
		declaredArguments = new Argument[] {
		    new Argument( false, "string", Key.key, "default" ),
		    new Argument( false, "boolean", ModuleKeys.forceNew, false )
		};
	}

	/**
	 * ExampleBIF
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 */
	public String _invoke( IBoxContext context, ArgumentsScope arguments ) {

		WebRequestBoxContext	requestContext	= context.getParentOfType( WebRequestBoxContext.class );

		String					tokenKey		= arguments.getAsString( Key.key );
		Boolean					forceNew		= arguments.getAsBoolean( ModuleKeys.forceNew );

		IStruct					moduleSettings	= runtime.getModuleService().getModuleSettings( Key.of( "csrf" ) );
		Key						storage			= Key.of( moduleSettings.getAsString( ModuleKeys.cacheStorage ) );
		SessionBoxContext		sessionContext	= context.getParentOfType( SessionBoxContext.class );
		Session					session			= sessionContext.getSession();
		Key						sessionId		= session.getID();
		IStruct					activeTokens;

		ICacheProvider			cacheProvider;
		String					cacheKey		= session.getCacheKey() + "_csrf_tokens";

		if ( storage.equals( ModuleKeys.session ) ) {
			cacheProvider = context.getParentOfType( RequestBoxContext.class ).getApplicationListener().getApplication().getSessionsCache();
		} else {
			cacheProvider = runtime.getCacheService().getCache( storage );
		}

		Object existing = cacheProvider.get( cacheKey );
		if ( existing == null ) {
			activeTokens = new Struct();
		} else {
			activeTokens = StructCaster.cast( existing );
		}

		activeTokens = activeTokens.entrySet().stream().filter( entry -> {
			DateTime expires = new DateTime( StructCaster.cast( entry.getValue() ).getAsString( Key.expires ) );
			return expires.getWrapped().isAfter( new DateTime().getWrapped() );
		} ).collect( BLCollector.toStruct() );

		Key assignment = Key.of( tokenKey );

		if ( forceNew || !activeTokens.containsKey( assignment ) ) {
			IStruct tokenStruct = Struct.of(
			    Key.token, generateNewToken( requestContext, sessionId.toString(), tokenKey, getRealIP( requestContext ) ),
			    Key.expires, new DateTime().modify( "m", moduleSettings.getAsLong( ModuleKeys.rotationInterval ) ).toISOString()
			);
			activeTokens.put( assignment, tokenStruct );
			cacheProvider.set( cacheKey, activeTokens );
			return tokenStruct.getAsString( Key.token );
		} else {
			return activeTokens.getAsStruct( assignment ).getAsString( Key.token );
		}

	}

	private String generateNewToken( RequestBoxContext context, String sessionId, String key, String realIP ) {
		IStruct	arguments	= Struct.of(
		    Key.number1, 0,
		    Key.number2, 65535,
		    Key.algorithm, rangeAlgorithm
		);
		Long	range		= LongCaster
		    .cast( runtime.getFunctionService().getGlobalFunction( ModuleKeys.randRange ).invoke( context, arguments, false, ModuleKeys.randRange ) );

		// Ensure tokenBase is sufficiently random for this user and could never be guessed
		String	tokenBase	= key + realIP + range.toString() + new DateTime().toEpochMillis().toString() + sessionId;
		String	hashedToken	= StringCaster.cast(
		    runtime.getFunctionService()
		        .getGlobalFunction( ModuleKeys.hash )
		        .invoke(
		            context,
		            Struct.of(
		                Key.input, tokenBase,
		                Key.algorithm, hashAlgorithm
		            ),
		            false,
		            ModuleKeys.hash
		        )
		);

		// Return a 40 character hash as the new token
		return hashedToken.substring( 0, 40 ).toUpperCase();

	}

	private String getRealIP( WebRequestBoxContext requestContext ) {
		IBoxHTTPExchange	exchange	= requestContext.getHTTPExchange();
		IStruct				headers		= new Struct();

		exchange.getRequestHeaderMap().forEach( ( key, values ) -> {
			headers.put( key, values[ 0 ] );
		} );

		IScope cgi = requestContext.getScope( ModuleKeys.cgi );

		if ( headers.containsKey( clusterClientIPKey ) ) {
			return headers.getAsString( clusterClientIPKey );
		} else if ( headers.containsKey( forwardedForKey ) ) {
			return headers.getAsString( forwardedForKey );
		} else {
			return cgi.getAsString( Key.remote_addr );
		}
	}

}
