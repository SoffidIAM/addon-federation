package com.soffid.iam.federation.idp;

import java.util.List;

import org.eclipse.jetty.servlet.ServletContextHandler;

public interface IdpWebExtension {
	List<IdpServletDescriptor> getServletDescriptors();
}
