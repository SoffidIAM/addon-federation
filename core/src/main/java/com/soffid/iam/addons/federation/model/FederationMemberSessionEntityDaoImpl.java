package com.soffid.iam.addons.federation.model;

import org.hibernate.Hibernate;

import com.soffid.iam.addons.federation.common.FederationMemberSession;

public class FederationMemberSessionEntityDaoImpl extends FederationMemberSessionEntityDaoBase {

	@Override
	public void toFederationMemberSession(FederationMemberSessionEntity source, FederationMemberSession target) {
		super.toFederationMemberSession(source, target);
		final FederationMemberEntity fm0 = source.getFederationMember();
		
		Long id = fm0.getId();
		getSession().evict(fm0);
		FederationMemberEntity fm = getFederationMemberEntityDao().load(id);
		
		
		if (fm instanceof IdentityProviderEntityImpl)
			target.setFederationMember(((IdentityProviderEntity)fm).getPublicId());
		else if (fm instanceof ServiceProviderEntityImpl)
			target.setFederationMember(((ServiceProviderEntity)fm).getPublicId());
	}

	@Override
	public void federationMemberSessionToEntity(FederationMemberSession source, FederationMemberSessionEntity target,
			boolean copyIfNull) {
		super.federationMemberSessionToEntity(source, target, copyIfNull);
		target.setFederationMember(null);
		if (source.getFederationMember() != null && !source.getFederationMember().trim().isEmpty())
			for (FederationMemberEntity fm: getFederationMemberEntityDao().findFMByPublicId(source.getFederationMember()))
				target.setFederationMember(fm);
	}
}
