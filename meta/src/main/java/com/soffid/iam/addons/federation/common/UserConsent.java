package com.soffid.iam.addons.federation.common;

import java.util.Date;

import com.soffid.mda.annotation.Description;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class UserConsent {
	@Nullable
	public java.lang.Long id;

	Long userId;
	
	@Description("Service provider")
	String serviceProvider;
	
	Date date;
}
