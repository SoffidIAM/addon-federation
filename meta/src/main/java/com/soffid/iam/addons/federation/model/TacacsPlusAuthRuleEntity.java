package com.soffid.iam.addons.federation.model;

import java.util.Collection;

import com.soffid.iam.addons.federation.common.TacacsPlusAuthRule;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.DaoFinder;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SC_FEDTAC")
@Depends({TacacsPlusAuthRule.class})
public class TacacsPlusAuthRuleEntity {
	@Nullable @Identifier
	@Column(name = "TAC_ID")
	Long id;
	
	@Column(name = "TAC_FED_ID",  reverseAttribute = "tacacsRules")
	FederationMemberEntity serviceProvider;
	
	@Column(name = "TAC_NAME", length = 50)
	String name;
	
	@Nullable
	@Column(name = "TAC_EXPRES", length = 128000)
	String expression;
	
	@Nullable
	@Column(name = "TAC_TEN_ID")
	TenantEntity tenant;
	
	@DaoFinder ("select a from com.soffid.iam.addons.federation.model.TacacsPlusAuthRuleEntity as a "
			+ "where a.serviceProvider.publicId = :serviceProvider and "
			+ "a.tenant.id = :tenantId")
	Collection<TacacsPlusAuthRuleEntity> findByServiceProvider(String serviceProvider) {
		return null;
	}
}
