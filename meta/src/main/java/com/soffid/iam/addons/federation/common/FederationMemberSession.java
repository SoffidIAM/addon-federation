package com.soffid.iam.addons.federation.common;

import com.soffid.iam.addons.federation.model.FederationMemberEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class FederationMemberSession {
	@Nullable
	Long id;
	
	Long sessionId;
	
	@Nullable
	String federationMember;
	
	@Nullable
	String userNameFormat;
	
	@Nullable
	String userNameQualifier;
	
	@Nullable
	String sessionHash;

	String userName;

}
