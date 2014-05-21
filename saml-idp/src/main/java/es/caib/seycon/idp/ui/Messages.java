package es.caib.seycon.idp.ui;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

import es.caib.seycon.ng.comu.lang.MessageFactory;

public class Messages {
	private static final String BUNDLE_NAME = "es.caib.seycon.idp.ui.messages"; //$NON-NLS-1$

	private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle
			.getBundle(BUNDLE_NAME);

	private Messages() {
	}

	public static String getString(String key) {
		ClassLoader ccl = Thread.currentThread().getContextClassLoader();
		try {
			Thread.currentThread().setContextClassLoader(Messages.class.getClassLoader());
			return MessageFactory.getString(BUNDLE_NAME, key);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		} finally {
			Thread.currentThread().setContextClassLoader(ccl);
		}
	}
}
