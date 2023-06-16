package com.soffid.iam.addons.federation.api;

import java.util.Date;

import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class UserCredentialChallenge {
	@Nullable @Identifier Long id;
	
	Date created;
	
	boolean solved;
}
