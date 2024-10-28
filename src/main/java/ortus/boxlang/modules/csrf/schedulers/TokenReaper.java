package ortus.boxlang.modules.csrf.schedulers;

import java.util.concurrent.TimeUnit;

import ortus.boxlang.modules.csrf.util.KeyDictionary;
import ortus.boxlang.runtime.BoxRuntime;
import ortus.boxlang.runtime.async.tasks.BaseScheduler;
import ortus.boxlang.runtime.cache.filters.WildcardFilter;
import ortus.boxlang.runtime.cache.providers.ICacheProvider;
import ortus.boxlang.runtime.dynamic.Attempt;
import ortus.boxlang.runtime.dynamic.casters.LongCaster;
import ortus.boxlang.runtime.dynamic.casters.StringCaster;
import ortus.boxlang.runtime.dynamic.casters.StructCaster;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.DateTime;
import ortus.boxlang.runtime.types.IStruct;
import ortus.boxlang.runtime.types.util.BLCollector;

public class TokenReaper extends BaseScheduler {

	private static BoxRuntime	runtime			= BoxRuntime.getInstance();
	IStruct						moduleSettings	= runtime.getModuleService().getModuleSettings( Key.of( "csrf" ) );

	public TokenReaper() {
		super( "CSRFTokenReaper" );
	}

	/**
	 * Declare the tasks for this scheduler
	 */
	@Override
	public void configure() {
		task( "Reap Expired Tokens" )
		    .call( () -> {
			    Key			storage			= Key.of( moduleSettings.getAsString( KeyDictionary.cacheStorage ) );
			    String		cacheKeyFilter	= "bl_csrf_tokens_*";

			    ICacheProvider cacheProvider = runtime.getCacheService().getCache( storage );
			    cacheProvider.getKeys( new WildcardFilter( cacheKeyFilter ) )
			        .stream()
			        .map( StringCaster::cast )
			        .forEach( key -> {
				        Attempt<Object> entry = cacheProvider.get( key );
				        if ( !entry.isNull() ) {
					        IStruct activeTokens = StructCaster.cast( entry.get() );
					        cacheProvider.set(
					            key,
					            activeTokens.entrySet().stream().filter( item -> {
						            DateTime expires = new DateTime( StructCaster.cast( item.getValue() ).getAsString( Key.expires ) );
						            expires.getWrapped().isAfter( new DateTime().getWrapped() );
						            return expires.getWrapped().isAfter( new DateTime().getWrapped() );
					            } ).collect( BLCollector.toStruct() )
					        );
				        }
			        } );
		    } )
		    .every( LongCaster.cast( moduleSettings.getAsNumber( KeyDictionary.reapFrequency ) ), TimeUnit.MINUTES )
		    .onFailure(
		        ( task, exception ) -> logger.error(
		            "An error occurred while attempt to perform cleanup on expired CSRF tokens. " + exception.getMessage(),
		            exception
		        )
		    )
		    .onSuccess(
		        ( task, result ) -> logger.debug( "Task [Reap Expired Tokens]: " + result )
		    );

	}

	/**
	 * Called before the scheduler is going to be shutdown
	 */
	@Override
	public void onShutdown() {
		logger.debug( "[onShutdown] ==> The CSRF TokenReaper has been shutdown" );
	}

	/**
	 * Called after the scheduler has registered all schedules
	 */
	@Override
	public void onStartup() {
		logger.debug( "[onStartup] ==> The CSRF TokenReaper has been started" );
	}

}
