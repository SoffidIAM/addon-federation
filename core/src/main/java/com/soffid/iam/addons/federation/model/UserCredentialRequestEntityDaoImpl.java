package com.soffid.iam.addons.federation.model;

import java.util.Date;

public class UserCredentialRequestEntityDaoImpl extends UserCredentialRequestEntityDaoBase {

	@Override
	protected void handleDeleteExpired() throws Exception {
		getSession().createQuery("delete from com.soffid.iam.addons.federation.model.UserCredentialRequestEntity "
				+ "where expiration < :now")
			.setParameter("now", new Date())
			.executeUpdate();
	}

}
