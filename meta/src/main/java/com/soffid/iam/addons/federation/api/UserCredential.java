package com.soffid.iam.addons.federation.api;

import java.util.Date;

import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class UserCredential {
	@Nullable
	Long id;
	
	Long userId;

	String serialNumber;
	
	String rawid;
	
	@Nullable
	String description;
	
	String key;
	
	@Nullable
	Date created;
	
	@Nullable
	Date lastUse;
}
