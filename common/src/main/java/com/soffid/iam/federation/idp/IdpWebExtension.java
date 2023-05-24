package com.soffid.iam.federation.idp;

import java.util.List;

public interface IdpWebExtension {
	List<IdpServletDescriptor> getServletDescriptors();
}
