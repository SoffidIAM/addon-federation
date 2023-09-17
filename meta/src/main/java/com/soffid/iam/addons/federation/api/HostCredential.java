package com.soffid.iam.addons.federation.api;

import java.security.cert.X509Certificate;
import java.util.Date;

import com.soffid.iam.addons.federation.common.UserCredentialType;
import com.soffid.mda.annotation.Description;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class HostCredential {
	@Nullable
	Long id;
	
	UserCredentialType type;
	
	Long hostId;

	String serialNumber;
	
	@Nullable
	String rawid;
	
	@Nullable
	String description;

	@Description("Key for FIDO Tokens")
	@Nullable
	String key;
	
	@Nullable
	@Description("Certificate")
	X509Certificate certificate;

	@Nullable
	Date created;
	
	@Nullable
	Date lastUse;

	@Nullable
	Date registerBefore;

	@Nullable
	public java.util.Calendar expirationDate;

}
