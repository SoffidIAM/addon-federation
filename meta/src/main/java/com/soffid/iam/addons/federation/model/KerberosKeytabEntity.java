//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.model;
import com.soffid.iam.addons.federation.common.KerberosKeytab;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.*;

@Entity (table="SC_KRKETB" )
@Depends ({ KerberosKeytab.class })
public abstract class KerberosKeytabEntity {

	@Column (name="KKT_ID")
	@Identifier
	public java.lang.Long id;

	@Column (name="KKT_DESCRI")
	@Nullable
	public java.lang.String description;

	@Column (name="KKT_PRINCI")
	@Nullable
	public java.lang.String principal;

	@Column (name="KKT_DOMAIN")
	@Nullable
	public java.lang.String domain;

	@Column (name="KKT_KEYTAB", length=64000)
	@Nullable
	public byte[]keyTab;
	
	@Column (name="KKT_FED_ID", reverseAttribute="keytabs")
	VirtualIdentityProviderEntity identityProvider;
}
