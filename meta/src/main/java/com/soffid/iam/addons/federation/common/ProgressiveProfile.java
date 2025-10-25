package com.soffid.iam.addons.federation.common;

import java.util.Collection;
import java.util.List;

import com.soffid.iam.addons.federation.model.VirtualIdentityProviderEntity;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Attribute;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class ProgressiveProfile {
	@Nullable
	Long id;

	@Nullable
	Long order;
	
	String name;
	
	@Nullable
	String condition;

	@Nullable
	String form;
	
	@Nullable
	String processDefinition;

	@Nullable
	@Attribute(defaultValue = "new java.util.LinkedList()")
	List<String> fields;
}
