package com.soffid.iam.addons.federation.common;

import java.util.List;

import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class AllowedScope {
	@Nullable Long id;
	
	String scope;
	
	List<String> roles;
}
