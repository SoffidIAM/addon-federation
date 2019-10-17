package bsh;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

import com.soffid.iam.addons.federation.api.adaptive.AdaptiveEnvironment;

/**
	A namespace which maintains an external map of values held in variables in
	its scope.  This mechanism provides a standard collections based interface
	to the namespace as well as a convenient way to export and view values of
	the namespace without the ordinary BeanShell wrappers.   
	</p>

	Variables are maintained internally in the normal fashion to support
	meta-information (such as variable type and visibility modifiers), but
	exported and imported in a synchronized way.  Variables are exported each
	time they are written by BeanShell.  Imported variables from the map appear
	in the BeanShell namespace as untyped variables with no modifiers and
	shadow any previously defined variables in the scope. 
	<p/>

	Note: this class is inherentely dependent on Java 1.2, however it is not
	used directly by the core as other than type NameSpace, so no dependency is
	introduced.
*/
/*
	Implementation notes:  bsh methods are not currently expored to the
	external namespace.  All that would be required to add this is to override
	setMethod() and provide a friendlier view than vector (currently used) for
	overloaded forms (perhaps a map by method SignatureKey).
*/
public class EnvironmentNamespace extends NameSpace
{
	private Map externalMap;
	private AdaptiveEnvironment env;
	private String[] vars = new String[] {
			"dayOfWeek",
			"daysSinceLastLogon",
			"daysSinceLastLogonFromSameHost",
			"failuresForSameIp",
			"failuresForSameUser",
			"failuresRatio",
			"hour",
			"identityProvider",
			"ipAddress",
			"minute",
			"newDevice",
			"sameCountry",
			"serviceProvider",
			"sourceCountry",
			"user"
			
	};

    public EnvironmentNamespace( AdaptiveEnvironment env) 
	{
		super( (NameSpace) null, "Adaptive Environment namespace");
		this.env = env;
	}

	/**
	*/
	public String [] getVariableNames() 
	{
		// union of the names in the internal namespace and external map
		Set nameSet = new HashSet();
		String [] nsNames = super.getVariableNames();
		nameSet.addAll( Arrays.asList( nsNames ) );
		for (String var: vars)
			nameSet.add( var );
		return (String [])nameSet.toArray( new String[0] );
	}

	/**
	*/
	/*
		Notes: This implmenetation of getVariableImpl handles the following
		cases:
		1) var in map not in local scope - var was added through map
		2) var in map and in local scope - var was added through namespace
		3) var not in map but in local scope - var was removed via map
		4) var not in map and not in local scope - non-existent var
	*/
    protected Variable getVariableImpl( String name, boolean recurse ) 
		throws UtilEvalError
	{
		// check the external map for the variable name
    	try {
    		Method m = env.getClass().getMethod(name, new Class[0]);
    		Object value = m.invoke(env, new Object[0]);
   			return  new Variable( name, (Class)null, value, (Modifiers)null );
    	} catch (NoSuchMethodException e) {
    		return super.getVariableImpl( name, recurse );
    	} catch (IllegalAccessException e) {
    		throw new UtilTargetError(e);
		} catch (IllegalArgumentException e) {
    		throw new UtilTargetError(e);
		} catch (InvocationTargetException e) {
    		throw new UtilTargetError(e);
		}
    }
	
}

