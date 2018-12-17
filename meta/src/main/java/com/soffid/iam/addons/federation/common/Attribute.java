//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.mda.annotation.*;

@ValueObject 
public class Attribute {

	@Nullable
	public java.lang.Long id;

	@Nullable
	public java.lang.String shortName;

	@Nullable
	public java.lang.String oid;

	@Nullable
	public java.lang.String name;

	@Nullable
	public java.lang.String openidName;
	

	@Nullable
	public java.lang.String value;

}
