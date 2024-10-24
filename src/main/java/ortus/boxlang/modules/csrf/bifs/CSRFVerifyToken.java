package ortus.boxlang.modules.csrf.bifs;

import ortus.boxlang.runtime.bifs.BIF;
import ortus.boxlang.runtime.bifs.BoxBIF;
import ortus.boxlang.runtime.context.IBoxContext;
import ortus.boxlang.runtime.scopes.ArgumentsScope;
import ortus.boxlang.runtime.scopes.Key;
import ortus.boxlang.runtime.types.Argument;

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
	public String _invoke( IBoxContext context, ArgumentsScope arguments ) {
		return "Hello from an ExampleJavaBIF!";
	}

}
