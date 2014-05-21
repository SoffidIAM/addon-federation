/**
 * 
 */
package com.soffid.iam.addons.federation.service;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * @author (C) Soffid 2013
 *
 */
public class Messages {
	private static final String BUNDLE_NAME = "com.soffid.iam.addons.federation.service.messages"; //$NON-NLS-1$

	private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle
			.getBundle(BUNDLE_NAME);

	private Messages() {
	}

	public static String getString(String key) {
		try {
			return RESOURCE_BUNDLE.getString(key);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}
}
