package com.soffid.iam.addons.federation.model;

import java.util.List;

import com.soffid.iam.addons.federation.common.FederationMemberSession;
import com.soffid.iam.model.TenantEntity;
import com.soffid.mda.annotation.Column;
import com.soffid.mda.annotation.DaoFinder;
import com.soffid.mda.annotation.Depends;
import com.soffid.mda.annotation.Entity;
import com.soffid.mda.annotation.Identifier;
import com.soffid.mda.annotation.Nullable;

@Entity(table = "SC_FEDSES")
@Depends({ FederationMemberSession.class})
public class FederationMemberSessionEntity {
	@Column(name="FSE_ID")
	@Nullable
	@Identifier
	Long id;
	
	@Column(name="FSE_SES_ID")
	Long sessionId;
	
	@Column(name="FSE_FED_ID", reverseAttribute = "sessions")
	FederationMemberEntity federationMember;
	
	@Column(name="FSE_USER")
	String userName;
	
	@Column(name="FSE_TEN_ID")
	TenantEntity tenant;
	
	@Nullable
	@Column(name="FSE_USEFOR")
	String userNameFormat;
	
	@Nullable
	@Column(name="FSE_USEQUA")
	String userNameQualifier;
	
	@Nullable
	@Column(name="FSE_SESHAS")
	String sessionHash;

	List<FederationMemberSessionEntity> findBySessionId(Long sessionId) { return null; }
	
	@DaoFinder("select fmse "
			+ "from com.soffid.iam.addons.federation.model.FederationMemberSessionEntity as fmse "
			+ "where fmse.userName = :uid and fmse.federationMember.publicId=:publicId and tenant.id = :tenantId")
	List<FederationMemberSessionEntity> findByUid(String publicId, String uid) { return null; }
}
