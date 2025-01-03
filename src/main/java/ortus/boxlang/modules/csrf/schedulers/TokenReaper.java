/**
 * [BoxLang]
 *
 * Copyright [2023] [Ortus Solutions, Corp]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ortus.boxlang.modules.csrf.schedulers;

import java.util.concurrent.TimeUnit;

import ortus.boxlang.modules.csrf.CSRFService;
import ortus.boxlang.modules.csrf.util.KeyDictionary;
import ortus.boxlang.runtime.BoxRuntime;
import ortus.boxlang.runtime.async.tasks.BaseScheduler;
import ortus.boxlang.runtime.dynamic.casters.LongCaster;
import ortus.boxlang.runtime.types.IStruct;

/**
 * TokenReaper - This scheduler is responsible for reaping expired CSRF tokens from the cache
 */
public class TokenReaper extends BaseScheduler {

	private static BoxRuntime	runtime			= BoxRuntime.getInstance();
	IStruct						moduleSettings	= runtime.getModuleService().getModuleSettings( KeyDictionary._MODULE_NAME );

	/**
	 * No argument constructor
	 */
	public TokenReaper() {
		super( "CSRFTokenReaper" );
	}

	/**
	 * Declare the tasks for this scheduler
	 */
	@Override
	public void configure() {
		task( "Reap Expired Tokens" )
		    .call( CSRFService::reap )
		    .every( LongCaster.cast( moduleSettings.getAsNumber( KeyDictionary.reapFrequency ) ), TimeUnit.MINUTES )
		    .onFailure(
		        ( task, exception ) -> this.logger.error(
		            "An error occurred while attempt to perform cleanup on expired CSRF tokens. " + exception.getMessage(),
		            exception
		        )
		    )
		    .onSuccess(
		        ( task, result ) -> this.logger.debug( "Task [Reaped Expired Tokens]" )
		    );

	}

	/**
	 * Called before the scheduler is going to be shutdown
	 */
	@Override
	public void onShutdown() {
		this.logger.debug( "[onShutdown] ==> The CSRF TokenReaper has been shutdown" );
	}

	/**
	 * Called after the scheduler has registered all schedules
	 */
	@Override
	public void onStartup() {
		this.logger.debug( "[onStartup] ==> The CSRF TokenReaper has been started" );
	}

}
