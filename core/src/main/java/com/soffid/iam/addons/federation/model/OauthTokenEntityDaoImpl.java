package com.soffid.iam.addons.federation.model;

import com.soffid.iam.addons.federation.common.OauthToken;

public class OauthTokenEntityDaoImpl extends OauthTokenEntityDaoBase {

	@Override
	public void toOauthToken(OauthTokenEntity source, OauthToken target) {
		super.toOauthToken(source, target);
		StringBuffer sb = null;
		for (OauthTokenScopeEntity scope: source.getScopes()) {
			if (sb == null) sb = new StringBuffer();
			else sb.append(" ");
			sb.append(scope.getScope());
		}
		if (sb != null)
			target.setScope(sb.toString());
	}

}
