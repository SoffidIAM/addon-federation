//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="SAML2SSOP" )
public abstract class Saml2SSOProfileEntity extends com.soffid.iam.addons.federation.model.Saml2AttributeQueryProfileEntity {

	@Column (name="PRO_MAXSELT")
	@Nullable
	public java.lang.String maximumSPSessionLifetime;

	@Column (name="PRO_IATSTA")
	@Nullable
	public boolean includeAttributeStatement;

}
