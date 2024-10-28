package ortus.boxlang.modules.csrf.bifs;

import ortus.boxlang.modules.csrf.util.KeyDictionary;
import ortus.boxlang.runtime.application.Session;
import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.cache.providers.ICacheProvider;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.context.RequestBoxContext;
import ortus.boxlang.runtime.context.SessionBoxContext;
import ortus.boxlang.runtime.dynamic.Attempt;
import ortus.boxlang.runtime.dynamic.casters.StructCaster;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.Argument;
import ortus.boxlang.runtime.types.DateTime;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.util.BLCollector;

@BoxBIF
public class CSRFVerifyToken extends BIF {

	public CSRFVerifyToken() {
		super();
		declaredArguments = new Argument[] {
		    new Argument( true, "string", Key.token ),
		    new Argument( false, "string", Key.key, "default" )
		};
	}

	/**
	 * ExampleBIF
	 *
	 * @param context   The context in which the BIF is being invoked.
	 * @param arguments Argument scope for the BIF.
	 */
	public Boolean _invoke( IBoxContext context, ArgumentsScope arguments ) {
		String				tokenKey		= arguments.getAsString( Key.key );
		IStruct				moduleSettings	= runtime.getModuleService().getModuleSettings( Key.of( "csrf" ) );
		Key					storage			= Key.of( moduleSettings.getAsString( KeyDictionary.cacheStorage ) );
		SessionBoxContext	sessionContext	= context.getParentOfType( SessionBoxContext.class );
		if ( sessionContext == null ) {
			throw new RuntimeException( "CSRF Tokens may not be generated or verified unless session management is enabled" );
		}
		Session			session		= sessionContext.getSession();
		IStruct			activeTokens;

		ICacheProvider	cacheProvider;
		String			cacheKey	= "bl_csrf_tokens_" + session.getCacheKey();

		if ( storage.equals( KeyDictionary.session ) ) {
			cacheProvider = context.getParentOfType( RequestBoxContext.class ).getApplicationListener().getApplication().getSessionsCache();
		} else {
			cacheProvider = runtime.getCacheService().getCache( storage );
		}

		Attempt<Object> existing = cacheProvider.get( cacheKey );
		if ( existing.isNull() ) {
			return false;
		} else {
			Key assignment = Key.of( tokenKey );

			activeTokens = StructCaster.cast( existing.get() ).entrySet().stream().filter( entry -> {
				DateTime expires = new DateTime( StructCaster.cast( entry.getValue() ).getAsString( Key.expires ) );
				expires.getWrapped().isAfter( new DateTime().getWrapped() );
				return expires.getWrapped().isAfter( new DateTime().getWrapped() );
			} ).collect( BLCollector.toStruct() );

			if ( activeTokens.containsKey( assignment ) ) {
				return activeTokens.getAsStruct( assignment ).getAsString( Key.token ).equals( arguments.getAsString( Key.token ) );
			} else {
				return false;
			}
		}

	}

}
