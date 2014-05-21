//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.mda.annotation.*;

@Entity (table="" ,
		discriminatorValue="SAML2ECPP" )
public abstract class Saml2ECPProfileEntity extends com.soffid.iam.addons.federation.model.Saml2AttributeQueryProfileEntity {

	@Column (name="PRO_IATSTA")
	@Nullable
	public boolean includeAttributeStatement;

	@Column (name="PRO_LOCADD")
	@Nullable
	public java.lang.String localityAddress;

	@Column (name="PRO_LOCDNS")
	@Nullable
	public java.lang.String localityDNSName;

}
