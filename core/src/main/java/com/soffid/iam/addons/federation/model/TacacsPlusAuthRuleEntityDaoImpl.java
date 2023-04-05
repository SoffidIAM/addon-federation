package com.soffid.iam.addons.federation.model;

import com.soffid.iam.addons.federation.common.TacacsPlusAuthRule;

import es.caib.seycon.ng.exception.SeyconException;

public class TacacsPlusAuthRuleEntityDaoImpl extends TacacsPlusAuthRuleEntityDaoBase {

	@Override
	public void toTacacsPlusAuthRule(TacacsPlusAuthRuleEntity source, TacacsPlusAuthRule target) {
		super.toTacacsPlusAuthRule(source, target);
		target.setServiceProvider(source.getServiceProvider().getPublicId());
	}

	@Override
	public void tacacsPlusAuthRuleToEntity(TacacsPlusAuthRule source, TacacsPlusAuthRuleEntity target,
			boolean copyIfNull) {
		super.tacacsPlusAuthRuleToEntity(source, target, copyIfNull);
		for (FederationMemberEntity fm: getFederationMemberEntityDao().findFMByPublicId(source.getServiceProvider())) {
			if (fm instanceof ServiceProviderEntity)
				target.setServiceProvider(fm);
		}
		if (target.getServiceProvider() == null)
			throw new SeyconException("Wrong federation member "+source.getServiceProvider());
	}

}
