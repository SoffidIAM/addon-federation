package com.soffid.iam.addons.federation.common;

import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Description;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;
import com.soffid.mda.annotation.ValueObject;

@ValueObject
public class TacacsPlusAuthRule {
	@Nullable @Identifier
	@Column(name = "TAC_ID")
	Long id;

	@Nullable
	String serviceProvider;
	
	@Column(name = "TAC_NAME", length = 50)
	String name;
	
	@Nullable
	@Description("Javascript expression to allow or not access")
	@Column(name = "TAC_EXPRES", length = 128000)
	String expression;

}
