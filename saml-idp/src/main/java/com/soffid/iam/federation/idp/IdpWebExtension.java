package com.soffid.iam.federation.idp;

import org.eclipse.jetty.servlet.ServletContextHandler;

public interface IdpWebExtension {
	void configure(ServletContextHandler ctx);
}
