//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="SAML1AQP" )
public abstract class Saml1AttributeQueryProfileEntity extends com.soffid.iam.addons.federation.model.SamlProfileEntity {

	@Column (name="PRO_OBATYPE")
	@Nullable
	public java.lang.String outboundArtifactType;

	@Column (name="PRO_ASLTIME")
	@Nullable
	public java.lang.String assertionLifetime;

}
