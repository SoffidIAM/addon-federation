package com.soffid.iam.addons.federation.model;

import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;

@Entity (table="SC_FEDURL")

public class ServiceProviderReturnUrlEntity {
	@Nullable @Identifier
	@Column(name="FEU_ID")
	Long id;
	
	@Column(name="FEU_FED_ID", reverseAttribute = "returnUrls")
	FederationMemberEntity federationMember;
	
	@Column(name="FEU_URL", length = 255)
	String url;

	@Nullable @Column(name="FEU_TYPE", length = 16)
	String type;
}
