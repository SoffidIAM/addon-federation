package com.soffid.iam.addons.federation.service;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import com.soffid.iam.addons.federation.api.adaptive.AdaptiveEnvironment;
import com.soffid.iam.sync.intf.ExtensibleObject;

import bsh.Modifiers;
import bsh.UtilTargetError;
import bsh.Variable;

public class EnvironmentExtensibleObject extends ExtensibleObject {

	private AdaptiveEnvironment env;

	public EnvironmentExtensibleObject(AdaptiveEnvironment env) {
		this.env = env;
	}

	@Override
	public Object getAttribute(String attribute) {
		Object obj = super.getAttribute(attribute);
		if (obj != null)
			return obj;
		// check the external map for the variable name
    	try {
    		Method m = env.getClass().getMethod(attribute, new Class[0]);
    		Object value = m.invoke(env, new Object[0]);
    		put(attribute, value);
    		return value;
    	} catch (NoSuchMethodException e) {
    		return super.getAttribute(attribute);
		} catch (InvocationTargetException e) {
    		return new RuntimeException("Error getting "+attribute, e);
		} catch (IllegalAccessException e) {
    		return super.getAttribute(attribute);
		} catch (IllegalArgumentException e) {
    		return super.getAttribute(attribute);
		}
	}

}
