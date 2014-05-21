//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="SAML2AQP" )
public abstract class Saml2AttributeQueryProfileEntity extends com.soffid.iam.addons.federation.model.Saml1AttributeQueryProfileEntity {

	@Column (name="PRO_APRCNT")
	@Nullable
	public java.lang.Long assertionProxyCount;

	@Column (name="PRO_ENCASS")
	@Nullable
	public java.lang.Long encryptAssertions;

	@Column (name="PRO_ENCNID")
	@Nullable
	public java.lang.Long encryptNameIds;

}
