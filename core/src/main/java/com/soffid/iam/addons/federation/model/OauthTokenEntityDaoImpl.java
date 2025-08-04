package com.soffid.iam.addons.federation.model;

import java.util.Date;
import java.util.List;

import org.hibernate.Query;

import com.soffid.iam.addons.federation.common.OauthToken;
import com.soffid.iam.model.TaskEntity;

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

	@Override
	protected void handleDeleteExpiredOauthTokens() {
		Date now = new Date();
		do {
			Query q = getSession().createQuery("select id "
					+ "from com.soffid.iam.addons.federation.model.OauthTokenEntityImpl "
					+ "where expires < :now");
			q.setTimestamp("now", now);
			q.setMaxResults(1000);
			List<Long> l = q.list();

			if (l.isEmpty())
				 return;
			
			q = getSession().createQuery("delete from com.soffid.iam.addons.federation.model.OauthTokenScopeEntityImpl "
					+ "where token.id in :l");
			q.setParameterList("l", l);
			q.executeUpdate();
			
			q = getSession().createQuery("delete from com.soffid.iam.addons.federation.model.OauthTokenEntityImpl "
					+ "where id in :l");
			q.setParameterList("l", l);
			q.executeUpdate();
		} while (System.currentTimeMillis() - now.getTime() < 60_000); // 1 minute maximum
	}
}
