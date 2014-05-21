//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.mda.annotation.*;

@Enumeration 
public class SAMLRequirementEnumeration {

	public Long NEVER=0L;

	public Long ALWAYS=1L;

	public Long CONDITIONAL=2L;

}
