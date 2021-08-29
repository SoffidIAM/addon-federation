//
// (C) 2013 Soffid
// 
// This file is licensed by Soffid under GPL v3 license
//

package com.soffid.iam.addons.federation.common;
import com.soffid.mda.annotation.*;

@ValueObject 
public class AttributePolicyCondition extends com.soffid.iam.addons.federation.common.PolicyCondition {
	@com.soffid.mda.annotation.Attribute(defaultValue = "Boolean.TRUE")
	public java.lang.Boolean allow;

}
