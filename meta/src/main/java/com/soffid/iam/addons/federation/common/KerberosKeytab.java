//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.mda.annotation.*;

@ValueObject 
public class KerberosKeytab {

	@Nullable
	public java.lang.Long id;

	@Nullable
	public java.lang.String description;

	@Nullable
	public java.lang.String principal;

	@Nullable
	public java.lang.String domain;

	@Nullable
	public byte[]keyTab;

}
